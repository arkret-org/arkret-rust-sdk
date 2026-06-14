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
        ServiceRoute {
            operation_id: $operation_id,
            method: method_str!($method),
            path: $path,
        }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServiceRoute {
    pub operation_id: &'static str,
    pub method: &'static str,
    pub path: &'static str,
}

// HTTP/JSON bindings for every operation in the canonical spec operation
// registry (`cokret-spec/spec/v1/artifacts/registry/operation-registry.json`),
// kept in the registry's own file order.
const SERVICE_ROUTES: &[ServiceRoute] = &[
    endpoint!(
        "ck.gate.account.command.register",
        Post,
        "/_cokret/gate/account/register"
    ),
    endpoint!(
        "ck.gate.account.command.pair_device",
        Post,
        "/_cokret/gate/account/device-pair"
    ),
    endpoint!(
        "ck.gate.account.command.issue_session_grant",
        Post,
        "/_cokret/gate/account/session-grants"
    ),
    endpoint!(
        "ck.gate.account.command.revoke_session",
        Post,
        "/_cokret/gate/account/session-grants/revoke"
    ),
    endpoint!(
        "ck.gate.account.command.pair_agent_key",
        Post,
        "/_cokret/gate/account/agent-key-pair"
    ),
    endpoint!(
        "ck.self.agent.command.provision",
        Post,
        "/_cokret/self/agents"
    ),
    endpoint!("ck.self.agent.query.list", Get, "/_cokret/self/agents"),
    endpoint!(
        "ck.self.agent.resource.get",
        Get,
        "/_cokret/self/agents/{agent_principal_id}"
    ),
    endpoint!(
        "ck.self.agent.command.pause",
        Post,
        "/_cokret/self/agents/{agent_principal_id}/pause"
    ),
    endpoint!(
        "ck.self.agent.command.resume",
        Post,
        "/_cokret/self/agents/{agent_principal_id}/resume"
    ),
    endpoint!(
        "ck.self.agent.command.deactivate",
        Post,
        "/_cokret/self/agents/{agent_principal_id}/deactivate"
    ),
    endpoint!(
        "ck.self.agent.command.rotate_key",
        Post,
        "/_cokret/self/agents/{agent_principal_id}/rotate-key"
    ),
    endpoint!(
        "ck.self.agent.grant.command.attach",
        Post,
        "/_cokret/self/agents/{agent_principal_id}/grants"
    ),
    endpoint!(
        "ck.self.agent.grant.resource.delete",
        Delete,
        "/_cokret/self/agents/{agent_principal_id}/grants/{grant_id}"
    ),
    endpoint!(
        "ck.self.agent.sidecar_thread.command.ensure",
        Post,
        "/_cokret/self/agent-sidecar-threads:ensure"
    ),
    endpoint!(
        "ck.self.agent.participation.resource.replace",
        Put,
        "/_cokret/self/agents/{agent_principal_id}/participation"
    ),
    endpoint!(
        "ck.self.agent.participation.resource.get",
        Get,
        "/_cokret/self/agents/{agent_principal_id}/participation"
    ),
    endpoint!(
        "ck.gate.account.exchange.complete_oidc",
        Post,
        "/_cokret/gate/account/oidc/callback"
    ),
    endpoint!(
        "ck.edge.applet.query.describe",
        Get,
        "/_cokret/edge/applet/describe"
    ),
    endpoint!(
        "ck.self.applet.install.command.preview",
        Post,
        "/_cokret/self/applets/install/preview"
    ),
    endpoint!(
        "ck.self.applet.command.install",
        Post,
        "/_cokret/self/applets/install"
    ),
    endpoint!(
        "ck.self.applet.ghost.command.provision",
        Post,
        "/_cokret/self/applets/{applet_id}/ghosts/provision"
    ),
    endpoint!(
        "ck.edge.applet.query.ping",
        Get,
        "/_cokret/edge/applet/ping"
    ),
    endpoint!(
        "ck.edge.applet.query.protocol_metadata",
        Get,
        "/_cokret/edge/applet/protocols/{protocol}"
    ),
    endpoint!(
        "ck.edge.applet.actor.query.resolve",
        Get,
        "/_cokret/edge/applet/actors/{actor_id}"
    ),
    endpoint!(
        "ck.edge.applet.realm.query.resolve",
        Get,
        "/_cokret/edge/applet/realms/{realm_id_or_alias}"
    ),
    endpoint!(
        "ck.self.applet.command.revoke",
        Post,
        "/_cokret/self/applets/{applet_id}/revoke"
    ),
    endpoint!(
        "ck.edge.applet.third_party_locations.query.list",
        Get,
        "/_cokret/edge/applet/third_party/locations"
    ),
    endpoint!(
        "ck.edge.applet.third_party_users.query.list",
        Get,
        "/_cokret/edge/applet/third_party/users"
    ),
    endpoint!(
        "ck.edge.applet.command.transaction",
        Post,
        "/_cokret/edge/applet/transactions"
    ),
    endpoint!(
        "ck.self.authz.query.check",
        Post,
        "/_cokret/self/authz/check"
    ),
    endpoint!(
        "ck.self.authz.grants.query.effective",
        Get,
        "/_cokret/self/authz/effective-grants"
    ),
    endpoint!(
        "ck.self.authz.invites.query.list",
        Get,
        "/_cokret/self/authz/invites"
    ),
    endpoint!("ck.self.blob.resource.get", Get, "/_cokret/self/blob/get"),
    endpoint!("ck.self.blob.resource.head", Head, "/_cokret/self/blob/get"),
    endpoint!(
        "ck.self.blob.upload.create",
        Post,
        "/_cokret/self/blob/upload"
    ),
    endpoint!(
        "ck.self.blob.command.presign",
        Post,
        "/_cokret/self/blob/presign"
    ),
    endpoint!(
        "ck.self.device_messages.query.list",
        Get,
        "/_cokret/self/device_messages"
    ),
    endpoint!(
        "ck.self.device_messages.command.send",
        Post,
        "/_cokret/self/device_messages"
    ),
    endpoint!(
        "ck.self.device_messages.command.ack",
        Post,
        "/_cokret/self/device_messages/ack"
    ),
    endpoint!(
        "ck.self.contact.command.request",
        Post,
        "/_cokret/self/contacts/request"
    ),
    endpoint!(
        "ck.self.contact.command.respond",
        Post,
        "/_cokret/self/contacts/respond"
    ),
    endpoint!("ck.self.contact.query.list", Get, "/_cokret/self/contacts"),
    endpoint!(
        "ck.self.contact.command.tombstone",
        Post,
        "/_cokret/self/contacts/tombstone"
    ),
    endpoint!(
        "ck.self.invite_receive_policy.resource.get",
        Get,
        "/_cokret/self/invite-receive-policy"
    ),
    endpoint!(
        "ck.self.invite_receive_policy.resource.replace",
        Post,
        "/_cokret/self/invite-receive-policy"
    ),
    endpoint!(
        "ck.self.direct_conversation.command.resolve",
        Post,
        "/_cokret/self/direct-conversations/resolve"
    ),
    endpoint!(
        "ck.find.directory.command.announce",
        Post,
        "/_cokret/find/directory/announce"
    ),
    endpoint!(
        "ck.find.directory.query.describe",
        Get,
        "/_cokret/find/directory/describe"
    ),
    endpoint!(
        "ck.find.directory.query.private_contact_discovery",
        Post,
        "/_cokret/find/directory/private-contact-discovery"
    ),
    endpoint!(
        "ck.find.directory.query.resolve_handle",
        Post,
        "/_cokret/find/directory/resolve-handle"
    ),
    endpoint!(
        "ck.find.directory.query.list_handles_for_subject",
        Post,
        "/_cokret/find/directory/list-handles-for-subject"
    ),
    endpoint!(
        "ck.find.directory.query.resolve_organization",
        Post,
        "/_cokret/find/directory/resolve-organization"
    ),
    endpoint!(
        "ck.find.directory.query.resolve_realm",
        Post,
        "/_cokret/find/directory/resolve-realm"
    ),
    endpoint!(
        "ck.find.directory.query.resolve_target",
        Post,
        "/_cokret/find/directory/resolve-target"
    ),
    endpoint!(
        "ck.find.directory.query.search_actors",
        Post,
        "/_cokret/find/directory/search-actors"
    ),
    endpoint!(
        "ck.find.directory.query.search_organizations",
        Post,
        "/_cokret/find/directory/search-organizations"
    ),
    endpoint!(
        "ck.find.directory.query.search_realms",
        Post,
        "/_cokret/find/directory/search-realms"
    ),
    endpoint!(
        "ck.find.directory.query.search_users",
        Post,
        "/_cokret/find/directory/search-users"
    ),
    endpoint!(
        "ck.find.directory.push.command.register",
        Post,
        "/_cokret/find/directory/push/register"
    ),
    endpoint!(
        "ck.find.directory.command.withdraw",
        Post,
        "/_cokret/find/directory/withdraw"
    ),
    endpoint!(
        "ck.self.events.query.describe",
        Get,
        "/_cokret/self/events/describe"
    ),
    endpoint!(
        "ck.self.events.query.frontier",
        Get,
        "/_cokret/self/events/frontier"
    ),
    endpoint!(
        "ck.self.events.resource.get",
        Get,
        "/_cokret/self/events/{event_id}"
    ),
    endpoint!("ck.self.events.query.scan", Get, "/_cokret/self/events"),
    endpoint!(
        "ck.self.events.query.scan_body",
        Post,
        "/_cokret/self/events/query"
    ),
    endpoint!(
        "ck.self.events.query.resolve",
        Post,
        "/_cokret/self/events/resolve"
    ),
    endpoint!(
        "ck.self.events.stream.subscribe",
        Get,
        "/_cokret/self/events/subscribe"
    ),
    endpoint!(
        "ck.self.events.command.submit",
        Post,
        "/_cokret/self/events"
    ),
    endpoint!(
        "ck.peer.events.query.describe",
        Get,
        "/_cokret/peer/events/describe"
    ),
    endpoint!(
        "ck.peer.events.query.frontier",
        Get,
        "/_cokret/peer/events/frontier"
    ),
    endpoint!("ck.peer.events.query.scan", Get, "/_cokret/peer/events"),
    endpoint!(
        "ck.peer.events.query.scan_body",
        Post,
        "/_cokret/peer/events/query"
    ),
    endpoint!(
        "ck.peer.events.query.resolve",
        Post,
        "/_cokret/peer/events/resolve"
    ),
    endpoint!(
        "ck.peer.events.command.submit",
        Post,
        "/_cokret/peer/events"
    ),
    endpoint!(
        "ck.peer.invites.command.submit",
        Post,
        "/_cokret/peer/invites"
    ),
    endpoint!(
        "ck.peer.contacts.command.submit",
        Post,
        "/_cokret/peer/contacts"
    ),
    endpoint!(
        "ck.peer.snapshot.query.manifest_head",
        Get,
        "/_cokret/peer/snapshot/head"
    ),
    endpoint!(
        "ck.self.ephemeral.command.send",
        Post,
        "/_cokret/self/ephemeral"
    ),
    endpoint!(
        "ck.self.call.media.exchange.issue_token",
        Post,
        "/_cokret/self/rtc/token"
    ),
    endpoint!(
        "ck.root.identity.registry.query.describe",
        Get,
        "/_cokret/root/identity/describe"
    ),
    endpoint!(
        "ck.root.identity.document.resource.get",
        Get,
        "/_cokret/root/identity/document"
    ),
    endpoint!(
        "ck.root.identity.log.query.list",
        Get,
        "/_cokret/root/identity/log"
    ),
    endpoint!(
        "ck.root.identity.receipts.query.list",
        Get,
        "/_cokret/root/identity/receipts"
    ),
    endpoint!(
        "ck.root.identity.recovery_policy.resource.get",
        Get,
        "/_cokret/root/identity/recovery-policy"
    ),
    endpoint!(
        "ck.root.identity.recovery_policy.command.publish",
        Post,
        "/_cokret/root/identity/recovery-policy"
    ),
    endpoint!(
        "ck.root.identity.query.resolve",
        Post,
        "/_cokret/root/identity/resolve"
    ),
    endpoint!(
        "ck.root.identity.command.submit_did_operation",
        Post,
        "/_cokret/root/identity/submit-did-operation"
    ),
    endpoint!(
        "ck.root.identity.recovery_session.command.create",
        Post,
        "/_cokret/root/identity/recovery-sessions"
    ),
    endpoint!(
        "ck.root.identity.recovery_session.resource.get",
        Get,
        "/_cokret/root/identity/recovery-sessions/{recovery_session_id}"
    ),
    endpoint!(
        "ck.root.identity.recovery_session.command.submit_proof",
        Post,
        "/_cokret/root/identity/recovery-sessions/{recovery_session_id}/proofs"
    ),
    endpoint!(
        "ck.root.identity.recovery_session.command.complete",
        Post,
        "/_cokret/root/identity/recovery-sessions/{recovery_session_id}/complete"
    ),
    endpoint!(
        "ck.self.keys.command.claim",
        Post,
        "/_cokret/self/keys/claim"
    ),
    endpoint!(
        "ck.self.keys.backups.resource.delete",
        Delete,
        "/_cokret/self/keys/backups/{backup_id}"
    ),
    endpoint!(
        "ck.self.keys.backups.query.list",
        Get,
        "/_cokret/self/keys/backups"
    ),
    endpoint!(
        "ck.self.keys.backups.resource.replace",
        Put,
        "/_cokret/self/keys/backups/{backup_id}"
    ),
    endpoint!(
        "ck.self.keys.backups.command.unlock",
        Post,
        "/_cokret/self/keys/backups/{backup_id}/unlock"
    ),
    endpoint!(
        "ck.self.keys.keypackages.command.claim",
        Post,
        "/_cokret/self/keys/keypackages/claim"
    ),
    endpoint!(
        "ck.self.keys.keypackages.command.consume",
        Post,
        "/_cokret/self/keys/keypackages/consume"
    ),
    endpoint!(
        "ck.self.keys.keypackages.command.revoke",
        Post,
        "/_cokret/self/keys/keypackages/revoke"
    ),
    endpoint!(
        "ck.self.keys.keypackages.upload.create",
        Post,
        "/_cokret/self/keys/keypackages/upload"
    ),
    endpoint!(
        "ck.self.keys.query.lookup",
        Post,
        "/_cokret/self/keys/query"
    ),
    endpoint!(
        "ck.self.keys.upload.create",
        Post,
        "/_cokret/self/keys/upload"
    ),
    endpoint!(
        "ck.self.media.query.ice_config",
        Post,
        "/_cokret/self/rtc/ice-config"
    ),
    endpoint!(
        "ck.open.invite_locator.query.resolve",
        Post,
        "/_cokret/open/invite-locators/resolve"
    ),
    endpoint!(
        "ck.open.mimi.query.group_info",
        Get,
        "/_cokret/open/mimi/strands/{strand_id}/group-info"
    ),
    endpoint!(
        "ck.open.mimi.query.identifiers",
        Post,
        "/_cokret/open/mimi/identifiers/query"
    ),
    endpoint!(
        "ck.open.mimi.exchange.request_key_material",
        Post,
        "/_cokret/open/mimi/key-material"
    ),
    endpoint!(
        "ck.open.mimi.command.notify",
        Post,
        "/_cokret/open/mimi/strands/{strand_id}/notify"
    ),
    endpoint!(
        "ck.open.mimi.query.provider_directory",
        Get,
        "/_cokret/open/mimi/provider-directory"
    ),
    endpoint!(
        "ck.open.mimi.command.proxy_download",
        Post,
        "/_cokret/open/mimi/proxy-download"
    ),
    endpoint!(
        "ck.open.mimi.command.report_abuse",
        Post,
        "/_cokret/open/mimi/report-abuse"
    ),
    endpoint!(
        "ck.open.mimi.command.request_consent",
        Post,
        "/_cokret/open/mimi/consent/request"
    ),
    endpoint!(
        "ck.open.mimi.command.update_room",
        Put,
        "/_cokret/open/mimi/strands/{strand_id}/update"
    ),
    endpoint!(
        "ck.open.mimi.command.submit_message",
        Post,
        "/_cokret/open/mimi/strands/{strand_id}/messages"
    ),
    endpoint!(
        "ck.open.mimi.command.update_consent",
        Post,
        "/_cokret/open/mimi/consent/update"
    ),
    endpoint!(
        "ck.self.moderation.command.report",
        Post,
        "/_cokret/self/moderation/report"
    ),
    endpoint!(
        "ck.self.policy.query.check",
        Post,
        "/_cokret/self/policy/check"
    ),
    endpoint!(
        "ck.self.projection.strands.query.list",
        Get,
        "/_cokret/self/projection/strands"
    ),
    endpoint!(
        "ck.self.projection.morphs.query.list",
        Get,
        "/_cokret/self/projection/morphs"
    ),
    endpoint!(
        "ck.self.projection.document.resource.get",
        Get,
        "/_cokret/self/projection/documents/{morph_id}"
    ),
    endpoint!(
        "ck.self.projection.spaces.query.list",
        Get,
        "/_cokret/self/projection/spaces"
    ),
    endpoint!(
        "ck.self.views.collection_projection.command.materialize",
        Post,
        "/_cokret/self/views/{view_id}/projection"
    ),
    endpoint!(
        "ck.edge.push.command.notify",
        Post,
        "/_cokret/edge/push/notify"
    ),
    endpoint!(
        "ck.edge.push.command.register_device",
        Post,
        "/_cokret/edge/push/register-device"
    ),
    endpoint!(
        "ck.edge.push.command.unregister_device",
        Post,
        "/_cokret/edge/push/unregister-device"
    ),
    endpoint!("ck.server.query.describe", Get, "/_cokret/describe"),
    endpoint!(
        "ck.self.account.query.describe",
        Get,
        "/_cokret/self/account/describe"
    ),
    endpoint!(
        "ck.self.account.query.viewer",
        Get,
        "/_cokret/self/account/viewer"
    ),
    endpoint!(
        "ck.self.account.command.update_profile",
        Post,
        "/_cokret/self/account/profile"
    ),
    endpoint!(
        "ck.self.account.stream.subscribe",
        Get,
        "/_cokret/self/account/subscribe"
    ),
    endpoint!(
        "ck.self.account.command.revoke_cursor",
        Post,
        "/_cokret/self/account/cursor/revoke"
    ),
    endpoint!(
        "ck.self.snapshot.query.manifest_head",
        Get,
        "/_cokret/self/snapshot/head"
    ),
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
    // The cursor vector must be a real `ck:cursor:<base64url>` token that
    // passes `cokret_core::Cursor::decode` (encoding.md §8) — static tokens
    // would eventually fail the §8.3 rule-12 TTL/expiry checks, so mint a
    // fresh stateful-handle cursor per call.
    let valid_cursor = cokret_core::Cursor::new()
        .and_then(|cursor| cursor.encode())
        .expect("minting a golden cursor vector must succeed");
    vec![
        ProtocolGoldenVector {
            name: "cursor_prefix".to_owned(),
            profile: "ck.conformance.cursor.v1".to_owned(),
            input: json!({"cursor": valid_cursor}),
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
            // encoding.md §7: `^[0-9a-f]{12}-[0-9a-f]{4}-[0-9a-f]{8}$`.
            input: json!({"hlc": "01970e589d21-0004-a13f9c2e"}),
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
                (
                    "realms".to_owned(),
                    "ck:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
                ),
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
