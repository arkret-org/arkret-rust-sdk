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
    endpoint!("cx.server.describe", Get, "/api/v1/server/describe"),
    endpoint!("cx.identity.describe_registry", Get, "/api/v1/identity/describe"),
    endpoint!("cx.identity.resolve", Post, "/api/v1/identity/resolve"),
    endpoint!("cx.identity.get_document", Get, "/api/v1/identity/document"),
    endpoint!("cx.identity.get_log", Get, "/api/v1/identity/log"),
    endpoint!("cx.identity.submit_did_operation", Post, "/api/v1/identity/submit-did-operation"),
    endpoint!("cx.identity.get_receipts", Get, "/api/v1/identity/receipts"),
    // C17 (spec 2026-05-08, wire-breaking): cx.sync.client_sync → cx.sync.account
    // (path unchanged, op_id renamed); cx.sync.subscribe → cx.events.subscribe at
    // /api/v1/events/subscribe; cx.events.list + cx.sync.backfill folded into
    // cx.events.query at /api/v1/events with `direction: forward|backward`.
    endpoint!("cx.sync.account", Post, "/api/v1/sync"),
    endpoint!("cx.sync.describe", Get, "/api/v1/sync/describe"),
    endpoint!("cx.events.describe", Get, "/api/v1/events/describe"),
    endpoint!("cx.events.submit", Post, "/api/v1/events"),
    endpoint!("cx.events.get", Get, "/api/v1/events/{event_id}"),
    endpoint!("cx.events.batch_get", Post, "/api/v1/events/batch-get"),
    endpoint!("cx.events.frontier", Get, "/api/v1/events/frontier"),
    endpoint!("cx.events.subscribe", Get, "/api/v1/events/subscribe"),
    endpoint!("cx.events.query", Get, "/api/v1/events"),
    endpoint!("cx.sync.get_snapshot_head", Get, "/api/v1/sync/snapshot-head"),
    endpoint!("cx.directory.describe", Get, "/api/v1/directory/describe"),
    endpoint!("cx.directory.search_spaces", Post, "/api/v1/directory/search-spaces"),
    endpoint!("cx.directory.resolve_space", Post, "/api/v1/directory/resolve-space"),
    endpoint!("cx.directory.search_organizations", Post, "/api/v1/directory/search-organizations"),
    endpoint!("cx.directory.resolve_organization", Post, "/api/v1/directory/resolve-organization"),
    endpoint!("cx.directory.search_actors", Post, "/api/v1/directory/search-actors"),
    endpoint!("cx.directory.search_users", Get, "/api/v1/directory/search-users"),
    endpoint!("cx.directory.resolve_handle", Post, "/api/v1/directory/resolve-handle"),
    endpoint!(
        "cx.directory.private_contact_discovery",
        Post,
        "/api/v1/directory/private-contact-discovery"
    ),
    endpoint!("cx.directory.announce", Post, "/api/v1/directory/announce"),
    endpoint!("cx.directory.withdraw", Post, "/api/v1/directory/withdraw"),
    endpoint!("cx.blob.upload", Post, "/api/v1/blob/upload"),
    endpoint!("cx.blob.head", Head, "/api/v1/blob/get"),
    endpoint!("cx.blob.get", Get, "/api/v1/blob/get"),
    endpoint!("cx.push.register_device", Post, "/api/v1/push/register-device"),
    endpoint!("cx.push.unregister_device", Post, "/api/v1/push/unregister-device"),
    endpoint!("cx.push.notify", Post, "/api/v1/push/notify"),
    endpoint!("cx.device_messages.put", Post, "/api/v1/device_messages"),
    endpoint!("cx.device_messages.get", Get, "/api/v1/device_messages"),
    endpoint!("cx.keys.upload", Post, "/api/v1/keys/upload"),
    endpoint!("cx.keys.query", Post, "/api/v1/keys/query"),
    endpoint!("cx.keys.claim", Post, "/api/v1/keys/claim"),
    endpoint!("cx.keys.backups.put", Put, "/api/v1/keys/backups/{backup_id}"),
    endpoint!("cx.keys.backups.list", Get, "/api/v1/keys/backups"),
    endpoint!("cx.keys.backups.get", Get, "/api/v1/keys/backups/{backup_id}"),
    endpoint!("cx.keys.backups.delete", Delete, "/api/v1/keys/backups/{backup_id}"),
    endpoint!("cx.keys.keypackages.upload", Post, "/api/v1/keys/keypackages/upload"),
    endpoint!("cx.keys.keypackages.claim", Post, "/api/v1/keys/keypackages/claim"),
    endpoint!("cx.keys.keypackages.consume", Post, "/api/v1/keys/keypackages/consume"),
    endpoint!("cx.keys.keypackages.revoke", Post, "/api/v1/keys/keypackages/revoke"),
    endpoint!("cx.authz.get_effective_grants", Get, "/api/v1/authz/effective-grants"),
    endpoint!("cx.authz.get_invites", Get, "/api/v1/authz/invites"),
    endpoint!("cx.authz.check", Post, "/api/v1/authz/check"),
    endpoint!("cx.policy.check", Post, "/contrix/v1/check"),
    endpoint!("cx.media.ice_config", Post, "/contrix/v1/ice-config"),
    endpoint!("cx.moderation.report", Post, "/api/v1/moderation/report"),
    endpoint!("cx.mimi.provider_directory", Get, "/api/v1/mimi/provider-directory"),
    endpoint!("cx.mimi.key_material", Post, "/api/v1/mimi/key-material"),
    endpoint!("cx.mimi.room_update", Put, "/api/v1/mimi/rooms/{flow_id}/update"),
    endpoint!("cx.mimi.notify", Post, "/api/v1/mimi/rooms/{flow_id}/notify"),
    endpoint!("cx.mimi.submit_message", Post, "/api/v1/mimi/rooms/{flow_id}/messages"),
    endpoint!("cx.mimi.group_info", Get, "/api/v1/mimi/rooms/{flow_id}/group-info"),
    endpoint!("cx.mimi.request_consent", Post, "/api/v1/mimi/consent/request"),
    endpoint!("cx.mimi.update_consent", Post, "/api/v1/mimi/consent/update"),
    endpoint!("cx.mimi.identifier_query", Post, "/api/v1/mimi/identifiers/query"),
    endpoint!("cx.mimi.report_abuse", Post, "/api/v1/mimi/report-abuse"),
    endpoint!("cx.mimi.proxy_download", Post, "/api/v1/mimi/proxy-download"),
    endpoint!("cx.account.issue_session_grant", Post, "/api/v1/auth/account/session-grants"),
    endpoint!("cx.account.device_pair", Post, "/api/v1/auth/account/device-pair"),
    endpoint!("cx.account.oidc_callback", Post, "/api/v1/auth/account/oidc/callback"),
    endpoint!("cx.admin.get_server_status", Get, "/api/v1/admin/server/status"),
    endpoint!("cx.admin.update_account_status", Post, "/api/v1/admin/accounts/{account_id}/status"),
    endpoint!("cx.admin.revoke_device", Post, "/api/v1/admin/devices/{device_id}/revoke"),
    endpoint!("cx.admin.get_moderation_queue", Get, "/api/v1/admin/moderation/queue"),
    endpoint!("cx.applet.ping", Get, "/api/v1/applet/ping"),
    endpoint!("cx.applet.describe", Get, "/api/v1/applet/describe"),
    endpoint!("cx.applet.transaction", Post, "/api/v1/applet/transactions"),
    endpoint!("cx.applet.query_actor", Get, "/api/v1/applet/actors/{actor_id}"),
    endpoint!("cx.applet.query_space", Get, "/api/v1/applet/spaces/{space_id_or_alias}"),
    endpoint!("cx.applet.protocol_metadata", Get, "/api/v1/applet/protocols/{protocol}"),
    endpoint!("cx.applet.third_party_users", Get, "/api/v1/applet/third_party/users"),
    endpoint!("cx.applet.third_party_locations", Get, "/api/v1/applet/third_party/locations"),
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
            expected_error_code: "capability_denied".to_owned(),
        },
        WireConformanceVector {
            name: "encoded_path_separator_rejected".to_owned(),
            method: "PUT".to_owned(),
            path: "/api/v1/federation/transactions/txn_%2Fescape".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "identity_invalid_did_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/identity/resolve".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"did": "alice.example"}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "sync_stale_cursor_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"since": "cx:cursor:expired"}),
            expected_status: 410,
            expected_error_code: "cursor_expired".to_owned(),
        },
        WireConformanceVector {
            name: "directory_invalid_handle_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/directory/resolve-handle".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"handle": ""}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
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
            expected_error_code: "cursor_expired".to_owned(),
        },
        WireConformanceVector {
            name: "bad_digest_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/blob/upload".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Digest".to_owned(), "sha256:not-hex".to_owned())]),
            body: json!({"size": 4}),
            expected_status: 400,
            expected_error_code: "digest_mismatch".to_owned(),
        },
        WireConformanceVector {
            name: "push_bad_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/push/register-device".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer ".to_owned())]),
            body: json!({}),
            expected_status: 401,
            expected_error_code: "unauthenticated".to_owned(),
        },
        WireConformanceVector {
            name: "device_messages_invalid_txn_rejected".to_owned(),
            method: "PUT".to_owned(),
            path: "/api/v1/device_messages/txn_%2Fescape".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"messages": {}}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "keys_missing_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/keys/query".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({"device_keys": {}}),
            expected_status: 401,
            expected_error_code: "unauthenticated".to_owned(),
        },
        WireConformanceVector {
            name: "authz_invalid_actor_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/authz/check".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"actor_id": "alice", "action": "read", "resource": {}}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "policy_bad_digest_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/contrix/v1/check".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"request_canonical_hash": "sha256:not-hex"}),
            expected_status: 400,
            expected_error_code: "digest_mismatch".to_owned(),
        },
        WireConformanceVector {
            name: "media_missing_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/contrix/v1/ice-config".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({}),
            expected_status: 401,
            expected_error_code: "unauthenticated".to_owned(),
        },
        WireConformanceVector {
            name: "moderation_invalid_space_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/moderation/report".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({"space_id": "room", "target_ref": "x", "reason": "spam", "reporter": "did:web:alice.example"}),
            expected_status: 400,
            expected_error_code: "invalid_param".to_owned(),
        },
        WireConformanceVector {
            name: "applet_missing_idempotency_key_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/applet/transactions".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({}),
            expected_status: 428,
            expected_error_code: "missing_param".to_owned(),
        },
        WireConformanceVector {
            name: "missing_idempotency_key_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/sync".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::from([("Authorization".to_owned(), "Bearer redacted".to_owned())]),
            body: json!({}),
            expected_status: 428,
            expected_error_code: "missing_param".to_owned(),
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
            expected_error_code: "duplicate_conflict".to_owned(),
        },
    ]
}
