//! Server-side protocol endpoint registry.
//!
//! This module is intentionally framework-free. HTTP servers can use these
//! contracts to keep route registration and advertised operation IDs aligned
//! with the protocol without pulling a web stack into the SDK.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointMethod {
    Get,
    Head,
    Post,
    Put,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointContract {
    pub operation_id: &'static str,
    pub method: EndpointMethod,
    pub path: &'static str,
}

pub const ENDPOINT_CONTRACTS: &[EndpointContract] = &[
    EndpointContract {
        operation_id: "cx.server.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/server/describe",
    },
    EndpointContract {
        operation_id: "cx.identity.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/identity/describe",
    },
    EndpointContract {
        operation_id: "cx.identity.resolve",
        method: EndpointMethod::Post,
        path: "/api/v1/identity/resolve",
    },
    EndpointContract {
        operation_id: "cx.identity.get_document",
        method: EndpointMethod::Get,
        path: "/api/v1/identity/document",
    },
    EndpointContract {
        operation_id: "cx.identity.get_log",
        method: EndpointMethod::Get,
        path: "/api/v1/identity/log",
    },
    EndpointContract {
        operation_id: "cx.identity.submit_did_operation",
        method: EndpointMethod::Post,
        path: "/api/v1/identity/submit-did-operation",
    },
    EndpointContract {
        operation_id: "cx.identity.get_receipts",
        method: EndpointMethod::Get,
        path: "/api/v1/identity/receipts",
    },
    EndpointContract {
        operation_id: "cx.repo.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/repo/describe",
    },
    EndpointContract {
        operation_id: "cx.repo.list_commits",
        method: EndpointMethod::Get,
        path: "/api/v1/repo/commits",
    },
    EndpointContract {
        operation_id: "cx.repo.get_commit",
        method: EndpointMethod::Get,
        path: "/api/v1/repo/commit",
    },
    EndpointContract {
        operation_id: "cx.repo.get_operations",
        method: EndpointMethod::Post,
        path: "/api/v1/repo/operations",
    },
    EndpointContract {
        operation_id: "cx.repo.sync",
        method: EndpointMethod::Post,
        path: "/api/v1/repo/sync",
    },
    EndpointContract {
        operation_id: "cx.repo.submit_commit",
        method: EndpointMethod::Post,
        path: "/api/v1/repo/submit-commit",
    },
    EndpointContract {
        operation_id: "cx.sync.client_sync",
        method: EndpointMethod::Post,
        path: "/api/v1/sync",
    },
    EndpointContract {
        operation_id: "cx.sync.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/sync/describe",
    },
    EndpointContract {
        operation_id: "cx.sync.subscribe",
        method: EndpointMethod::Get,
        path: "/api/v1/sync/subscribe",
    },
    EndpointContract {
        operation_id: "cx.sync.backfill",
        method: EndpointMethod::Get,
        path: "/api/v1/sync/backfill",
    },
    EndpointContract {
        operation_id: "cx.sync.get_snapshot_head",
        method: EndpointMethod::Get,
        path: "/api/v1/sync/snapshot-head",
    },
    EndpointContract {
        operation_id: "cx.federation.transaction",
        method: EndpointMethod::Put,
        path: "/api/v1/federation/transactions/{txn_id}",
    },
    EndpointContract {
        operation_id: "cx.federation.push_operations",
        method: EndpointMethod::Post,
        path: "/api/v1/federation/push-operations",
    },
    EndpointContract {
        operation_id: "cx.federation.pull_operations",
        method: EndpointMethod::Get,
        path: "/api/v1/federation/pull-operations",
    },
    EndpointContract {
        operation_id: "cx.federation.space_members",
        method: EndpointMethod::Get,
        path: "/api/v1/federation/space-members",
    },
    EndpointContract {
        operation_id: "cx.federation.verify_actor",
        method: EndpointMethod::Post,
        path: "/api/v1/federation/verify-actor",
    },
    EndpointContract {
        operation_id: "cx.index.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/index/describe",
    },
    EndpointContract {
        operation_id: "cx.index.entity",
        method: EndpointMethod::Get,
        path: "/api/v1/index/entity",
    },
    EndpointContract {
        operation_id: "cx.index.query",
        method: EndpointMethod::Post,
        path: "/api/v1/index/query",
    },
    EndpointContract {
        operation_id: "cx.index.thread",
        method: EndpointMethod::Get,
        path: "/api/v1/index/thread",
    },
    EndpointContract {
        operation_id: "cx.index.notifications",
        method: EndpointMethod::Get,
        path: "/api/v1/index/notifications",
    },
    EndpointContract {
        operation_id: "cx.index.inbox",
        method: EndpointMethod::Get,
        path: "/api/v1/index/inbox",
    },
    EndpointContract {
        operation_id: "cx.index.search",
        method: EndpointMethod::Post,
        path: "/api/v1/index/search",
    },
    EndpointContract {
        operation_id: "cx.index.space_hierarchy",
        method: EndpointMethod::Get,
        path: "/api/v1/index/space-hierarchy",
    },
    EndpointContract {
        operation_id: "cx.directory.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/directory/describe",
    },
    EndpointContract {
        operation_id: "cx.directory.search_spaces",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/search-spaces",
    },
    EndpointContract {
        operation_id: "cx.directory.resolve_space",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/resolve-space",
    },
    EndpointContract {
        operation_id: "cx.directory.search_organizations",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/search-organizations",
    },
    EndpointContract {
        operation_id: "cx.directory.resolve_organization",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/resolve-organization",
    },
    EndpointContract {
        operation_id: "cx.directory.search_actors",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/search-actors",
    },
    EndpointContract {
        operation_id: "cx.directory.search_users",
        method: EndpointMethod::Get,
        path: "/api/v1/directory/search-users",
    },
    EndpointContract {
        operation_id: "cx.directory.resolve_handle",
        method: EndpointMethod::Post,
        path: "/api/v1/directory/resolve-handle",
    },
    EndpointContract {
        operation_id: "cx.blob.upload",
        method: EndpointMethod::Post,
        path: "/api/v1/blob/upload",
    },
    EndpointContract {
        operation_id: "cx.blob.head",
        method: EndpointMethod::Head,
        path: "/api/v1/blob/get",
    },
    EndpointContract {
        operation_id: "cx.blob.get",
        method: EndpointMethod::Get,
        path: "/api/v1/blob/get",
    },
    EndpointContract {
        operation_id: "cx.push.register_device",
        method: EndpointMethod::Post,
        path: "/api/v1/push/register-device",
    },
    EndpointContract {
        operation_id: "cx.push.unregister_device",
        method: EndpointMethod::Post,
        path: "/api/v1/push/unregister-device",
    },
    EndpointContract {
        operation_id: "cx.push.notify",
        method: EndpointMethod::Post,
        path: "/api/v1/push/notify",
    },
    EndpointContract {
        operation_id: "cx.device_messages.put",
        method: EndpointMethod::Put,
        path: "/api/v1/device_messages/{txn_id}",
    },
    EndpointContract {
        operation_id: "cx.device_messages.get",
        method: EndpointMethod::Get,
        path: "/api/v1/device_messages",
    },
    EndpointContract {
        operation_id: "cx.keys.upload",
        method: EndpointMethod::Post,
        path: "/api/v1/keys/upload",
    },
    EndpointContract {
        operation_id: "cx.keys.query",
        method: EndpointMethod::Post,
        path: "/api/v1/keys/query",
    },
    EndpointContract {
        operation_id: "cx.keys.claim",
        method: EndpointMethod::Post,
        path: "/api/v1/keys/claim",
    },
    EndpointContract {
        operation_id: "cx.authz.effective_grants",
        method: EndpointMethod::Get,
        path: "/api/v1/authz/effective-grants",
    },
    EndpointContract {
        operation_id: "cx.authz.get_invites",
        method: EndpointMethod::Get,
        path: "/api/v1/authz/invites",
    },
    EndpointContract {
        operation_id: "cx.authz.check",
        method: EndpointMethod::Post,
        path: "/api/v1/authz/check",
    },
    EndpointContract {
        operation_id: "cx.policy.check",
        method: EndpointMethod::Post,
        path: "/contrix/v1/check",
    },
    EndpointContract {
        operation_id: "cx.media.ice_config",
        method: EndpointMethod::Post,
        path: "/contrix/v1/ice-config",
    },
    EndpointContract {
        operation_id: "cx.moderation.report",
        method: EndpointMethod::Post,
        path: "/api/v1/moderation/report",
    },
    EndpointContract {
        operation_id: "cx.applet.ping",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/ping",
    },
    EndpointContract {
        operation_id: "cx.applet.describe",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/describe",
    },
    EndpointContract {
        operation_id: "cx.applet.transaction",
        method: EndpointMethod::Put,
        path: "/api/v1/applet/transactions/{txn_id}",
    },
    EndpointContract {
        operation_id: "cx.applet.query_actor",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/actors/{actor_id}",
    },
    EndpointContract {
        operation_id: "cx.applet.query_space",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/spaces/{space_id_or_alias}",
    },
    EndpointContract {
        operation_id: "cx.applet.query_protocol",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/protocols/{protocol}",
    },
];

pub fn endpoint_contracts() -> &'static [EndpointContract] {
    ENDPOINT_CONTRACTS
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn endpoint_operation_ids_are_unique() {
        let mut ids = BTreeSet::new();
        for endpoint in endpoint_contracts() {
            assert!(ids.insert(endpoint.operation_id), "duplicate {}", endpoint.operation_id);
            assert!(
                endpoint.path.starts_with("/api/v1/") || endpoint.path.starts_with("/contrix/v1/")
            );
        }
    }
}
