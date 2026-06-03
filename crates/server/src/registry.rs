use super::*;

macro_rules! method_str {
    (Get) => {
        "get"
    };
    (Head) => {
        "head"
    };
    (Post) => {
        "post"
    };
    (Put) => {
        "put"
    };
    (Delete) => {
        "delete"
    };
}

macro_rules! endpoint {
    ($operation_id:literal, $method:ident, $path:literal) => {
        ServiceRoute { operation_id: $operation_id, method: method_str!($method), path: $path }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServiceRoute {
    pub operation_id: &'static str,
    pub method: &'static str,
    pub path: &'static str,
}

const SERVICE_ROUTES: &[ServiceRoute] = &[
    endpoint!("ck.server.describe", Get, "/_cokret/describe"),
    endpoint!("ck.identity.describe_registry", Get, "/_cokret/root/identity/describe"),
    endpoint!("ck.identity.resolve", Post, "/_cokret/root/identity/resolve"),
    endpoint!("ck.identity.get_document", Get, "/_cokret/root/identity/document"),
    endpoint!("ck.identity.get_log", Get, "/_cokret/root/identity/log"),
    endpoint!(
        "ck.identity.submit_did_operation",
        Post,
        "/_cokret/root/identity/submit-did-operation"
    ),
    endpoint!("ck.identity.get_receipts", Get, "/_cokret/root/identity/receipts"),
    endpoint!("ck.account.describe", Get, "/_cokret/self/account/describe"),
    endpoint!("ck.account.subscribe", Get, "/_cokret/self/account/subscribe"),
    endpoint!("ck.events.describe", Get, "/_cokret/self/events/describe"),
    endpoint!("ck.events.submit", Post, "/_cokret/self/events"),
    endpoint!("ck.events.get", Get, "/_cokret/self/events/{event_id}"),
    endpoint!("ck.events.resolve", Post, "/_cokret/self/events/resolve"),
    endpoint!("ck.events.frontier", Get, "/_cokret/self/events/frontier"),
    endpoint!("ck.events.subscribe", Get, "/_cokret/self/events/subscribe"),
    endpoint!("ck.events.query", Get, "/_cokret/self/events/query"),
    endpoint!("ck.snapshot.head", Get, "/_cokret/self/snapshot/head"),
    endpoint!("ck.directory.describe", Get, "/_cokret/find/directory/describe"),
    endpoint!("ck.directory.search_realms", Post, "/_cokret/find/directory/search-realms"),
    endpoint!("ck.directory.resolve_realm", Post, "/_cokret/find/directory/resolve-realm"),
    // R3.3 (CXP-0011, cokret-spec @ cced4b8). gRPC `Directory/ResolveTarget`
    // and MQ `directory.resolve_target` mirrors live in the spec
    // operation-registry; this HTTP route is the SDK-side binding.
    endpoint!("ck.directory.resolve_target", Post, "/_cokret/find/directory/resolve-target"),
    endpoint!(
        "ck.directory.search_organizations",
        Post,
        "/_cokret/find/directory/search-organizations"
    ),
    endpoint!(
        "ck.directory.resolve_organization",
        Post,
        "/_cokret/find/directory/resolve-organization"
    ),
    endpoint!("ck.directory.search_actors", Post, "/_cokret/find/directory/search-actors"),
    endpoint!("ck.directory.search_users", Post, "/_cokret/find/directory/search-users"),
    endpoint!("ck.directory.resolve_handle", Post, "/_cokret/find/directory/resolve-handle"),
    endpoint!(
        "ck.directory.private_contact_discovery",
        Post,
        "/_cokret/find/directory/private-contact-discovery"
    ),
    endpoint!("ck.directory.announce", Post, "/_cokret/find/directory/announce"),
    endpoint!("ck.directory.withdraw", Post, "/_cokret/find/directory/withdraw"),
    endpoint!("ck.directory.push.register", Post, "/_cokret/find/directory/push/register"),
    endpoint!("ck.blob.upload", Post, "/_cokret/self/blob/upload"),
    endpoint!("ck.blob.head", Head, "/_cokret/self/blob/get"),
    endpoint!("ck.blob.get", Get, "/_cokret/self/blob/get"),
    endpoint!("ck.push.register_device", Post, "/_cokret/edge/push/register-device"),
    endpoint!("ck.push.unregister_device", Post, "/_cokret/edge/push/unregister-device"),
    endpoint!("ck.push.notify", Post, "/_cokret/edge/push/notify"),
    endpoint!("ck.device_messages.put", Post, "/_cokret/self/device_messages"),
    endpoint!("ck.device_messages.get", Get, "/_cokret/self/device_messages"),
    endpoint!("ck.keys.upload", Post, "/_cokret/self/keys/upload"),
    endpoint!("ck.keys.query", Post, "/_cokret/self/keys/query"),
    endpoint!("ck.keys.claim", Post, "/_cokret/self/keys/claim"),
    endpoint!("ck.keys.backups.put", Put, "/_cokret/self/keys/backups/{backup_id}"),
    endpoint!("ck.keys.backups.list", Get, "/_cokret/self/keys/backups"),
    endpoint!("ck.keys.backups.get", Get, "/_cokret/self/keys/backups/{backup_id}"),
    endpoint!("ck.keys.backups.delete", Delete, "/_cokret/self/keys/backups/{backup_id}"),
    endpoint!("ck.keys.keypackages.upload", Post, "/_cokret/self/keys/keypackages/upload"),
    endpoint!("ck.keys.keypackages.claim", Post, "/_cokret/self/keys/keypackages/claim"),
    endpoint!("ck.keys.keypackages.consume", Post, "/_cokret/self/keys/keypackages/consume"),
    endpoint!("ck.keys.keypackages.revoke", Post, "/_cokret/self/keys/keypackages/revoke"),
    endpoint!("ck.authz.get_effective_grants", Get, "/_cokret/self/authz/effective-grants"),
    endpoint!("ck.authz.get_invites", Get, "/_cokret/self/authz/invites"),
    endpoint!("ck.authz.check", Post, "/_cokret/self/authz/check"),
    endpoint!("ck.policy.check", Post, "/_cokret/self/policy/check"),
    endpoint!("ck.media.ice_config", Post, "/_cokret/self/rtc/ice-config"),
    // CXP-0010 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec).
    endpoint!("ck.call.media.token_exchange", Post, "/_cokret/self/rtc/token"),
    endpoint!("ck.moderation.report", Post, "/_cokret/self/moderation/report"),
    endpoint!("ck.mimi.provider_directory", Get, "/_cokret/open/mimi/provider-directory"),
    endpoint!("ck.mimi.key_material", Post, "/_cokret/open/mimi/key-material"),
    endpoint!("ck.mimi.room_update", Put, "/_cokret/open/mimi/flows/{flow_id}/update"),
    endpoint!("ck.mimi.notify", Post, "/_cokret/open/mimi/flows/{flow_id}/notify"),
    endpoint!("ck.mimi.submit_message", Post, "/_cokret/open/mimi/flows/{flow_id}/messages"),
    endpoint!("ck.mimi.group_info", Get, "/_cokret/open/mimi/flows/{flow_id}/group-info"),
    endpoint!("ck.mimi.request_consent", Post, "/_cokret/open/mimi/consent/request"),
    endpoint!("ck.mimi.update_consent", Post, "/_cokret/open/mimi/consent/update"),
    endpoint!("ck.mimi.identifier_query", Post, "/_cokret/open/mimi/identifiers/query"),
    endpoint!("ck.mimi.report_abuse", Post, "/_cokret/open/mimi/report-abuse"),
    endpoint!("ck.mimi.proxy_download", Post, "/_cokret/open/mimi/proxy-download"),
    endpoint!("ck.account.issue_session_grant", Post, "/_cokret/gate/account/session-grants"),
    endpoint!("ck.account.device_pair", Post, "/_cokret/gate/account/device-pair"),
    endpoint!("ck.account.oidc_callback", Post, "/_cokret/gate/account/oidc/callback"),
    // Admin is a deployment-local namespace served under the `local` trust
    // segment (`/_cokret/local/admin/*`), per cokret-spec
    // service-http-binding.md §2.1.
    endpoint!("ck.admin.get_server_status", Get, "/_cokret/local/admin/server/status"),
    endpoint!(
        "ck.admin.update_account_status",
        Post,
        "/_cokret/local/admin/accounts/{account_id}/status"
    ),
    endpoint!("ck.admin.revoke_device", Post, "/_cokret/local/admin/devices/{device_id}/revoke"),
    endpoint!("ck.admin.get_moderation_queue", Get, "/_cokret/local/admin/moderation/queue"),
    endpoint!("ck.applet.ping", Get, "/_cokret/edge/applet/ping"),
    endpoint!("ck.applet.describe", Get, "/_cokret/edge/applet/describe"),
    endpoint!("ck.applet.transaction", Post, "/_cokret/edge/applet/transactions"),
    endpoint!("ck.applet.resolve_actor", Get, "/_cokret/edge/applet/actors/{actor_id}"),
    endpoint!("ck.applet.resolve_realm", Get, "/_cokret/edge/applet/realms/{realm_id_or_alias}"),
    endpoint!("ck.applet.protocol_metadata", Get, "/_cokret/edge/applet/protocols/{protocol}"),
    endpoint!("ck.applet.third_party_users", Get, "/_cokret/edge/applet/third_party/users"),
    endpoint!("ck.applet.third_party_locations", Get, "/_cokret/edge/applet/third_party/locations"),
    endpoint!("ck.account.cursor_revoke", Post, "/_cokret/self/account/cursor/revoke"),
];

pub(crate) fn service_routes() -> &'static [ServiceRoute] {
    SERVICE_ROUTES
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
            return Err(cokret_core::Error::Protocol(
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
            input: json!({"cursor": "ck:cursor:sync:01JS0SP000000000000000000"}),
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
            path: "/_cokret/describe".to_owned(),
            query: BTreeMap::from([("access_token".to_owned(), "redacted".to_owned())]),
            headers: BTreeMap::new(),
            body: Value::Null,
            expected_status: 400,
            expected_error_code: "capability_denied".to_owned(),
        },
        WireConformanceVector {
            name: "encoded_path_separator_rejected".to_owned(),
            method: "PUT".to_owned(),
            path: "/_cokret/peer/federation/transactions/txn_%2Fescape".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "identity_invalid_did_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/root/identity/resolve".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"did": "alice.example"}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "account_subscribe_stale_cursor_rejected".to_owned(),
            method: "GET".to_owned(),
            path: "/_cokret/self/account/subscribe".to_owned(),
            query: BTreeMap::from([("after".to_owned(), "ck:cursor:expired".to_owned())]),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: Value::Null,
            expected_status: 410,
            expected_error_code: "cursor_expired".to_owned(),
        },
        WireConformanceVector {
            name: "directory_invalid_handle_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/find/directory/resolve-handle".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"handle": ""}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "stale_cursor_rejected".to_owned(),
            method: "GET".to_owned(),
            path: "/_cokret/peer/federation/pull-operations".to_owned(),
            query: BTreeMap::from([
                ("space_id".to_owned(), "ck:space:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                ("after_cursor".to_owned(), "ck:cursor:expired".to_owned()),
            ]),
            headers: BTreeMap::new(),
            body: Value::Null,
            expected_status: 410,
            expected_error_code: "cursor_expired".to_owned(),
        },
        WireConformanceVector {
            name: "bad_digest_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/self/blob/upload".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Digest".to_owned(), "sha256:not-hex".to_owned())]),
            body: json!({"size": 4}),
            expected_status: 400,
            expected_error_code: "digest_mismatch".to_owned(),
        },
        WireConformanceVector {
            name: "push_bad_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/edge/push/register-device".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer ".to_owned())]),
            body: json!({}),
            expected_status: 401,
            expected_error_code: "unauthenticated".to_owned(),
        },
        WireConformanceVector {
            name: "device_messages_invalid_txn_rejected".to_owned(),
            method: "PUT".to_owned(),
            path: "/_cokret/self/device_messages/txn_%2Fescape".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"messages": {}}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "keys_missing_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/self/keys/query".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({"device_keys": {}}),
            expected_status: 401,
            expected_error_code: "unauthenticated".to_owned(),
        },
        WireConformanceVector {
            name: "authz_invalid_actor_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/self/authz/check".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"actor_id": "alice", "action": "read", "resource": {}}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "policy_bad_digest_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/self/policy/check".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"request_canonical_digest": "sha256:not-hex"}),
            expected_status: 400,
            expected_error_code: "digest_mismatch".to_owned(),
        },
        WireConformanceVector {
            name: "media_missing_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/self/rtc/ice-config".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({}),
            expected_status: 401,
            expected_error_code: "unauthenticated".to_owned(),
        },
        WireConformanceVector {
            name: "moderation_invalid_space_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/self/moderation/report".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"space_id": "room", "target_ref": "x", "reason": "spam", "reporter": "did:web:alice.example"}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "applet_missing_idempotency_key_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/edge/applet/transactions".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({}),
            expected_status: 428,
            expected_error_code: "missing_param".to_owned(),
        },
        WireConformanceVector {
            name: "missing_idempotency_key_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/self/events".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({}),
            expected_status: 428,
            expected_error_code: "missing_param".to_owned(),
        },
        WireConformanceVector {
            name: "idempotency_conflict_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/_cokret/self/events".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([
                ("Authorization".to_owned(), "Bearer redacted".to_owned()),
                ("Idempotency-Key".to_owned(), "sync-1".to_owned()),
            ]),
            body: json!({"conflict": true}),
            expected_status: 409,
            expected_error_code: "duplicate_conflict".to_owned(),
        },
    ]
}
