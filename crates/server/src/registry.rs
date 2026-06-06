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
    endpoint!("ck.root.identity.describe_registry", Get, "/_cokret/root/identity/describe"),
    endpoint!("ck.root.identity.resolve", Post, "/_cokret/root/identity/resolve"),
    endpoint!("ck.root.identity.get_document", Get, "/_cokret/root/identity/document"),
    endpoint!("ck.root.identity.get_log", Get, "/_cokret/root/identity/log"),
    endpoint!(
        "ck.root.identity.submit_did_operation",
        Post,
        "/_cokret/root/identity/submit-did-operation"
    ),
    endpoint!("ck.root.identity.get_receipts", Get, "/_cokret/root/identity/receipts"),
    endpoint!("ck.self.account.describe", Get, "/_cokret/self/account/describe"),
    endpoint!("ck.self.account.subscribe", Get, "/_cokret/self/account/subscribe"),
    endpoint!("ck.self.events.describe", Get, "/_cokret/self/events/describe"),
    endpoint!("ck.self.events.submit", Post, "/_cokret/self/events"),
    endpoint!("ck.self.events.get", Get, "/_cokret/self/events/{event_id}"),
    endpoint!("ck.self.events.resolve", Post, "/_cokret/self/events/resolve"),
    endpoint!("ck.self.events.frontier", Get, "/_cokret/self/events/frontier"),
    endpoint!("ck.self.events.subscribe", Get, "/_cokret/self/events/subscribe"),
    endpoint!("ck.self.events.query", Get, "/_cokret/self/events"),
    endpoint!("ck.self.events.query_post", Post, "/_cokret/self/events/query"),
    endpoint!("ck.self.snapshot.head", Get, "/_cokret/self/snapshot/head"),
    endpoint!("ck.find.directory.describe", Get, "/_cokret/find/directory/describe"),
    endpoint!("ck.find.directory.search_realms", Post, "/_cokret/find/directory/search-realms"),
    endpoint!("ck.find.directory.resolve_realm", Post, "/_cokret/find/directory/resolve-realm"),
    // R3.3 (CKP-0011, cokret-spec @ cced4b8). gRPC `Directory/ResolveTarget`
    // and MQ `directory.resolve_target` mirrors live in the spec
    // operation-registry; this HTTP route is the SDK-side binding.
    endpoint!("ck.find.directory.resolve_target", Post, "/_cokret/find/directory/resolve-target"),
    endpoint!(
        "ck.find.directory.search_organizations",
        Post,
        "/_cokret/find/directory/search-organizations"
    ),
    endpoint!(
        "ck.find.directory.resolve_organization",
        Post,
        "/_cokret/find/directory/resolve-organization"
    ),
    endpoint!("ck.find.directory.search_actors", Post, "/_cokret/find/directory/search-actors"),
    endpoint!("ck.find.directory.search_users", Post, "/_cokret/find/directory/search-users"),
    endpoint!("ck.find.directory.resolve_handle", Post, "/_cokret/find/directory/resolve-handle"),
    endpoint!(
        "ck.find.directory.private_contact_discovery",
        Post,
        "/_cokret/find/directory/private-contact-discovery"
    ),
    endpoint!("ck.find.directory.announce", Post, "/_cokret/find/directory/announce"),
    endpoint!("ck.find.directory.withdraw", Post, "/_cokret/find/directory/withdraw"),
    endpoint!("ck.find.directory.push.register", Post, "/_cokret/find/directory/push/register"),
    endpoint!("ck.self.blob.upload", Post, "/_cokret/self/blob/upload"),
    endpoint!("ck.self.blob.head", Head, "/_cokret/self/blob/get"),
    endpoint!("ck.self.blob.get", Get, "/_cokret/self/blob/get"),
    endpoint!("ck.edge.push.register_device", Post, "/_cokret/edge/push/register-device"),
    endpoint!("ck.edge.push.unregister_device", Post, "/_cokret/edge/push/unregister-device"),
    endpoint!("ck.edge.push.notify", Post, "/_cokret/edge/push/notify"),
    endpoint!("ck.self.device_messages.put", Post, "/_cokret/self/device_messages"),
    endpoint!("ck.self.device_messages.get", Get, "/_cokret/self/device_messages"),
    endpoint!("ck.self.keys.upload", Post, "/_cokret/self/keys/upload"),
    endpoint!("ck.self.keys.query", Post, "/_cokret/self/keys/query"),
    endpoint!("ck.self.keys.claim", Post, "/_cokret/self/keys/claim"),
    endpoint!("ck.self.keys.backups.put", Put, "/_cokret/self/keys/backups/{backup_id}"),
    endpoint!("ck.self.keys.backups.list", Get, "/_cokret/self/keys/backups"),
    endpoint!("ck.self.keys.backups.get", Get, "/_cokret/self/keys/backups/{backup_id}"),
    endpoint!("ck.self.keys.backups.delete", Delete, "/_cokret/self/keys/backups/{backup_id}"),
    endpoint!("ck.self.keys.keypackages.upload", Post, "/_cokret/self/keys/keypackages/upload"),
    endpoint!("ck.self.keys.keypackages.claim", Post, "/_cokret/self/keys/keypackages/claim"),
    endpoint!("ck.self.keys.keypackages.consume", Post, "/_cokret/self/keys/keypackages/consume"),
    endpoint!("ck.self.keys.keypackages.revoke", Post, "/_cokret/self/keys/keypackages/revoke"),
    endpoint!("ck.self.authz.get_effective_grants", Get, "/_cokret/self/authz/effective-grants"),
    endpoint!("ck.self.authz.get_invites", Get, "/_cokret/self/authz/invites"),
    endpoint!("ck.self.authz.check", Post, "/_cokret/self/authz/check"),
    endpoint!("ck.self.policy.check", Post, "/_cokret/self/policy/check"),
    endpoint!("ck.self.media.ice_config", Post, "/_cokret/self/rtc/ice-config"),
    // CKP-0010 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec).
    endpoint!("ck.self.call.media.token_exchange", Post, "/_cokret/self/rtc/token"),
    endpoint!("ck.self.moderation.report", Post, "/_cokret/self/moderation/report"),
    endpoint!("ck.open.mimi.provider_directory", Get, "/_cokret/open/mimi/provider-directory"),
    endpoint!("ck.open.mimi.key_material", Post, "/_cokret/open/mimi/key-material"),
    endpoint!("ck.open.mimi.room_update", Put, "/_cokret/open/mimi/flows/{flow_id}/update"),
    endpoint!("ck.open.mimi.notify", Post, "/_cokret/open/mimi/flows/{flow_id}/notify"),
    endpoint!("ck.open.mimi.submit_message", Post, "/_cokret/open/mimi/flows/{flow_id}/messages"),
    endpoint!("ck.open.mimi.group_info", Get, "/_cokret/open/mimi/flows/{flow_id}/group-info"),
    endpoint!("ck.open.mimi.request_consent", Post, "/_cokret/open/mimi/consent/request"),
    endpoint!("ck.open.mimi.update_consent", Post, "/_cokret/open/mimi/consent/update"),
    endpoint!("ck.open.mimi.identifier_query", Post, "/_cokret/open/mimi/identifiers/query"),
    endpoint!("ck.open.mimi.report_abuse", Post, "/_cokret/open/mimi/report-abuse"),
    endpoint!("ck.open.mimi.proxy_download", Post, "/_cokret/open/mimi/proxy-download"),
    endpoint!("ck.gate.account.issue_session_grant", Post, "/_cokret/gate/account/session-grants"),
    endpoint!("ck.gate.account.device_pair", Post, "/_cokret/gate/account/device-pair"),
    endpoint!("ck.gate.account.oidc_callback", Post, "/_cokret/gate/account/oidc/callback"),
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
    endpoint!("ck.edge.applet.ping", Get, "/_cokret/edge/applet/ping"),
    endpoint!("ck.edge.applet.describe", Get, "/_cokret/edge/applet/describe"),
    endpoint!("ck.edge.applet.transaction", Post, "/_cokret/edge/applet/transactions"),
    endpoint!("ck.edge.applet.resolve_actor", Get, "/_cokret/edge/applet/actors/{actor_id}"),
    endpoint!(
        "ck.edge.applet.resolve_realm",
        Get,
        "/_cokret/edge/applet/realms/{realm_id_or_alias}"
    ),
    endpoint!("ck.edge.applet.protocol_metadata", Get, "/_cokret/edge/applet/protocols/{protocol}"),
    endpoint!("ck.edge.applet.third_party_users", Get, "/_cokret/edge/applet/third_party/users"),
    endpoint!(
        "ck.edge.applet.third_party_locations",
        Get,
        "/_cokret/edge/applet/third_party/locations"
    ),
    endpoint!("ck.self.account.cursor_revoke", Post, "/_cokret/self/account/cursor/revoke"),
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
            profile: "ck.conformance.cursor.v1".to_owned(),
            input: json!({"cursor": "ck:cursor:sync:01JS0SP000000000000000000"}),
            expected: json!({"valid": true}),
        },
        ProtocolGoldenVector {
            name: "canonical_digest_prefix".to_owned(),
            profile: "ck.conformance.digest.v1".to_owned(),
            input: json!({"hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}),
            expected: json!({"valid": true, "algorithm": "sha256"}),
        },
        ProtocolGoldenVector {
            name: "canonical_json_object_order".to_owned(),
            profile: "ck.conformance.canonical_json.v1".to_owned(),
            input: json!({"b": 2, "a": 1}),
            expected: json!({"canonical": "{\"a\":1,\"b\":2}"}),
        },
        ProtocolGoldenVector {
            name: "hlc_shape".to_owned(),
            profile: "ck.conformance.hlc.v1".to_owned(),
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
            path: "/_cokret/peer/events/resolve%2Fescape".to_owned(),
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
            path: "/_cokret/peer/events".to_owned(),
            query: BTreeMap::from([
                ("realms".to_owned(), "ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned()),
                ("after".to_owned(), "ck:cursor:expired".to_owned()),
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
