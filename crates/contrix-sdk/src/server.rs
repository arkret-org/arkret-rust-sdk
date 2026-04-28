//! Server-side protocol endpoint registry.
//!
//! This module is intentionally framework-free. HTTP servers can use these
//! contracts to keep route registration and advertised operation IDs aligned
//! with the protocol without pulling a web stack into the SDK.

use serde_json::{Value, json};

use crate::{
    AppletActorResponse, AppletDescription, AppletPingResponse, AppletProtocolResponse,
    AppletSpaceResponse, AppletTransactionRequest, AppletTransactionResponse, AuthzCheckRequest,
    AuthzCheckResponse, AuthzInvitesResponse, BlobMetadata, BlobUploadMetadata, BlobUploadResponse,
    DeviceMessagesReceiveResponse, DeviceMessagesSendRequest, DeviceMessagesSendResponse,
    DirectoryDescription, DirectoryResolveHandleRequest, DirectoryResolveHandleResponse,
    DirectoryResolveOrganizationRequest, DirectoryResolveOrganizationResponse,
    DirectoryResolveSpaceRequest, DirectoryResolveSpaceResponse, DirectorySearchActorsRequest,
    DirectorySearchActorsResponse, DirectorySearchOrganizationsRequest,
    DirectorySearchOrganizationsResponse, DirectorySearchSpacesRequest,
    DirectorySearchSpacesResponse, DirectorySearchUsersResponse, EffectiveGrantsResponse,
    FederationPullOperationsResponse, FederationPushOperationsRequest,
    FederationPushOperationsResponse, FederationSpaceMembersResponse, FederationTransactionRequest,
    FederationTransactionResponse, FederationVerifyActorRequest, FederationVerifyActorResponse,
    IdentityDescription, IdentityDocumentResponse, IdentityLogResponse, IdentityReceiptsResponse,
    IdentityResolveRequest, IdentityResolveResponse, IndexDescription, IndexEntityResponse,
    IndexInboxResponse, IndexNotificationsResponse, IndexSearchRequest, IndexSearchResponse,
    IndexSpaceHierarchyResponse, IndexThreadResponse, KeysClaimRequest, KeysClaimResponse,
    KeysQueryRequest, KeysQueryResponse, KeysUploadRequest, KeysUploadResponse,
    MediaIceConfigRequest, MediaIceConfigResponse, ModerationReportRequest,
    ModerationReportResponse, OkResponse, PolicyCheckRequest, PolicyCheckResponse,
    PushNotifyRequest, PushNotifyResponse, PushRegisterDeviceRequest, PushRegisterDeviceResponse,
    PushUnregisterDeviceRequest, QueryRequest, QueryResponse, RepoCommitResponse,
    RepoCommitsResponse, RepoDescription, RepoOperationsRequest, RepoOperationsResponse,
    RepoSyncRequest, RepoSyncResponse, Result, ServerDescription, SubmitCommitResponse,
    SubmitDidOperationRequest, SubmitDidOperationResponse, SyncBackfillResponse, SyncDescription,
    SyncRequest, SyncResponse, SyncSnapshotHeadResponse,
};

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
        operation_id: "cx.identity.describe_registry",
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
        operation_id: "cx.index.get_entity",
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
        operation_id: "cx.authz.get_effective_grants",
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
        operation_id: "cx.applet.protocol_metadata",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/protocols/{protocol}",
    },
    EndpointContract {
        operation_id: "cx.applet.third_party_users",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/third_party/users",
    },
    EndpointContract {
        operation_id: "cx.applet.third_party_locations",
        method: EndpointMethod::Get,
        path: "/api/v1/applet/third_party/locations",
    },
];

pub fn endpoint_contracts() -> &'static [EndpointContract] {
    ENDPOINT_CONTRACTS
}

impl EndpointMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Head => "head",
            Self::Post => "post",
            Self::Put => "put",
        }
    }
}

#[derive(Clone, Debug)]
pub enum ServerRequest {
    ServerDescribe,
    IdentityDescribe,
    IdentityResolve(IdentityResolveRequest),
    IdentityDocument { did: String, version: Option<String> },
    IdentityLog { did: String, cursor: Option<String>, limit: Option<u32> },
    IdentitySubmitDidOperation(SubmitDidOperationRequest),
    IdentityReceipts { did: String, head: String },
    RepoDescribe { repo_id: Option<String> },
    RepoCommits { repo_id: String, cursor: Option<String>, limit: Option<u32> },
    RepoCommit { commit_id: String, repo_id: Option<String> },
    RepoOperations(RepoOperationsRequest),
    RepoSync(RepoSyncRequest),
    RepoSubmitCommit(crate::Commit),
    Sync(SyncRequest),
    SyncDescribe,
    SyncBackfill { space_id: String, cursor: Option<String>, limit: Option<u32> },
    SyncSnapshotHead { space_id: String },
    FederationTransaction { txn_id: String, request: FederationTransactionRequest },
    FederationPushOperations(FederationPushOperationsRequest),
    FederationPullOperations { space_id: String, after_cursor: Option<String>, limit: Option<u32> },
    FederationSpaceMembers { space_id: String, cursor: Option<String>, limit: Option<u32> },
    FederationVerifyActor(FederationVerifyActorRequest),
    IndexDescribe,
    IndexEntity { entity_id: String, space_id: Option<String>, at: Option<String> },
    IndexQuery(Box<QueryRequest>),
    IndexThread { topic_id: String, cursor: Option<String>, limit: Option<u32> },
    IndexNotifications { cursor: Option<String>, state: Option<String>, limit: Option<u32> },
    IndexInbox { scope: Option<String>, cursor: Option<String>, limit: Option<u32> },
    IndexSearch(IndexSearchRequest),
    IndexSpaceHierarchy { space_id: String, depth: Option<u32>, include_unconfirmed: Option<bool> },
    DirectoryDescribe,
    DirectorySearchSpaces(DirectorySearchSpacesRequest),
    DirectoryResolveSpace(DirectoryResolveSpaceRequest),
    DirectorySearchOrganizations(DirectorySearchOrganizationsRequest),
    DirectoryResolveOrganization(DirectoryResolveOrganizationRequest),
    DirectorySearchActors(DirectorySearchActorsRequest),
    DirectorySearchUsers { q: String, space_id: Option<String>, limit: Option<u32> },
    DirectoryResolveHandle(DirectoryResolveHandleRequest),
    BlobUpload { metadata: BlobUploadMetadata, bytes: Option<Vec<u8>> },
    BlobHead { blob_ref: String },
    BlobGet { blob_ref: String, range: Option<String> },
    PushRegisterDevice(PushRegisterDeviceRequest),
    PushUnregisterDevice(PushUnregisterDeviceRequest),
    PushNotify(PushNotifyRequest),
    DeviceMessagesPut { txn_id: String, request: DeviceMessagesSendRequest },
    DeviceMessagesGet { from: Option<String>, limit: Option<u32> },
    KeysUpload(KeysUploadRequest),
    KeysQuery(KeysQueryRequest),
    KeysClaim(KeysClaimRequest),
    AuthzEffectiveGrants { space_id: String, subject: String, at: Option<String> },
    AuthzInvites { subject: String, space_id: Option<String>, cursor: Option<String> },
    AuthzCheck(AuthzCheckRequest),
    PolicyCheck(PolicyCheckRequest),
    MediaIceConfig(MediaIceConfigRequest),
    ModerationReport(ModerationReportRequest),
    AppletPing,
    AppletDescribe,
    AppletTransaction { txn_id: String, request: AppletTransactionRequest },
    AppletActor { actor_id: String },
    AppletSpace { space_id_or_alias: String },
    AppletProtocol { protocol: String },
    AppletThirdPartyUsers,
    AppletThirdPartyLocations,
}

#[derive(Clone, Debug)]
pub enum ServerResponse {
    ServerDescription(ServerDescription),
    IdentityDescription(IdentityDescription),
    IdentityResolve(IdentityResolveResponse),
    IdentityDocument(IdentityDocumentResponse),
    IdentityLog(IdentityLogResponse),
    SubmitDidOperation(SubmitDidOperationResponse),
    IdentityReceipts(IdentityReceiptsResponse),
    RepoDescription(RepoDescription),
    RepoCommits(RepoCommitsResponse),
    RepoCommit(RepoCommitResponse),
    RepoOperations(RepoOperationsResponse),
    RepoSync(RepoSyncResponse),
    SubmitCommit(SubmitCommitResponse),
    Sync(SyncResponse),
    SyncDescription(SyncDescription),
    SyncBackfill(SyncBackfillResponse),
    SyncSnapshotHead(SyncSnapshotHeadResponse),
    FederationTransaction(FederationTransactionResponse),
    FederationPushOperations(FederationPushOperationsResponse),
    FederationPullOperations(FederationPullOperationsResponse),
    FederationSpaceMembers(FederationSpaceMembersResponse),
    FederationVerifyActor(FederationVerifyActorResponse),
    IndexDescription(IndexDescription),
    IndexEntity(IndexEntityResponse),
    IndexQuery(QueryResponse<Value>),
    IndexThread(IndexThreadResponse),
    IndexNotifications(IndexNotificationsResponse),
    IndexInbox(IndexInboxResponse),
    IndexSearch(IndexSearchResponse),
    IndexSpaceHierarchy(IndexSpaceHierarchyResponse),
    DirectoryDescription(DirectoryDescription),
    DirectorySearchSpaces(DirectorySearchSpacesResponse),
    DirectoryResolveSpace(DirectoryResolveSpaceResponse),
    DirectorySearchOrganizations(DirectorySearchOrganizationsResponse),
    DirectoryResolveOrganization(DirectoryResolveOrganizationResponse),
    DirectorySearchActors(DirectorySearchActorsResponse),
    DirectorySearchUsers(DirectorySearchUsersResponse),
    DirectoryResolveHandle(DirectoryResolveHandleResponse),
    BlobUpload(BlobUploadResponse),
    BlobHead(BlobMetadata),
    BlobBytes(Vec<u8>),
    PushRegisterDevice(PushRegisterDeviceResponse),
    Ok(OkResponse),
    PushNotify(PushNotifyResponse),
    DeviceMessagesSend(DeviceMessagesSendResponse),
    DeviceMessagesReceive(DeviceMessagesReceiveResponse),
    KeysUpload(KeysUploadResponse),
    KeysQuery(KeysQueryResponse),
    KeysClaim(KeysClaimResponse),
    EffectiveGrants(EffectiveGrantsResponse),
    AuthzInvites(AuthzInvitesResponse),
    AuthzCheck(AuthzCheckResponse),
    PolicyCheck(PolicyCheckResponse),
    MediaIceConfig(MediaIceConfigResponse),
    ModerationReport(ModerationReportResponse),
    AppletPing(AppletPingResponse),
    AppletDescription(AppletDescription),
    AppletTransaction(AppletTransactionResponse),
    AppletActor(AppletActorResponse),
    AppletSpace(AppletSpaceResponse),
    AppletProtocol(AppletProtocolResponse),
    AppletThirdPartyUsers(Value),
    AppletThirdPartyLocations(Value),
}

pub trait EndpointHandler {
    fn handle(&mut self, request: ServerRequest) -> Result<ServerResponse>;
}

pub fn openapi_document() -> Value {
    let mut paths = serde_json::Map::new();
    for endpoint in endpoint_contracts() {
        let mut methods = paths
            .remove(endpoint.path)
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        methods.insert(
            endpoint.method.as_str().to_owned(),
            json!({
                "operationId": endpoint.operation_id,
                "responses": {
                    "200": { "description": "Successful Contrix response" },
                    "400": { "$ref": "#/components/responses/ErrorEnvelope" },
                    "401": { "$ref": "#/components/responses/ErrorEnvelope" },
                    "403": { "$ref": "#/components/responses/ErrorEnvelope" },
                    "404": { "$ref": "#/components/responses/ErrorEnvelope" },
                    "405": { "$ref": "#/components/responses/ErrorEnvelope" },
                    "429": { "$ref": "#/components/responses/ErrorEnvelope" },
                    "503": { "$ref": "#/components/responses/ErrorEnvelope" }
                }
            }),
        );
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
            "responses": {
                "ErrorEnvelope": {
                    "description": "Standard Contrix error envelope",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["errcode", "error"],
                                "properties": {
                                    "errcode": { "type": "string" },
                                    "error": { "type": "string" },
                                    "retry_after_ms": { "type": "integer", "minimum": 0 }
                                },
                                "additionalProperties": true
                            }
                        }
                    }
                }
            },
            "securitySchemes": {
                "bearer": { "type": "http", "scheme": "bearer" },
                "deviceProof": { "type": "apiKey", "in": "header", "name": "X-Contrix-Device-Proof" },
                "serviceSignature": { "type": "apiKey", "in": "header", "name": "Signature" }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

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

    #[test]
    fn endpoint_registry_matches_required_spec_operations() {
        let actual = endpoint_contracts()
            .iter()
            .map(|endpoint| (endpoint.operation_id, endpoint.path))
            .collect::<BTreeMap<_, _>>();
        for (operation_id, path) in [
            ("cx.identity.resolve", "/api/v1/identity/resolve"),
            ("cx.repo.submit_commit", "/api/v1/repo/submit-commit"),
            ("cx.repo.get_operations", "/api/v1/repo/operations"),
            ("cx.sync.client_sync", "/api/v1/sync"),
            ("cx.sync.subscribe", "/api/v1/sync/subscribe"),
            ("cx.sync.backfill", "/api/v1/sync/backfill"),
            ("cx.federation.transaction", "/api/v1/federation/transactions/{txn_id}"),
            ("cx.index.query", "/api/v1/index/query"),
            ("cx.directory.resolve_handle", "/api/v1/directory/resolve-handle"),
            ("cx.blob.upload", "/api/v1/blob/upload"),
            ("cx.push.register_device", "/api/v1/push/register-device"),
            ("cx.device_messages.put", "/api/v1/device_messages/{txn_id}"),
            ("cx.keys.upload", "/api/v1/keys/upload"),
            ("cx.authz.check", "/api/v1/authz/check"),
            ("cx.policy.check", "/contrix/v1/check"),
            ("cx.media.ice_config", "/contrix/v1/ice-config"),
            ("cx.moderation.report", "/api/v1/moderation/report"),
            ("cx.applet.transaction", "/api/v1/applet/transactions/{txn_id}"),
        ] {
            assert_eq!(actual.get(operation_id), Some(&path), "{operation_id}");
        }
    }

    #[test]
    fn openapi_document_contains_standard_error_envelope() {
        let document = openapi_document();
        assert_eq!(document["openapi"], "3.1.0");
        assert!(document["paths"]["/api/v1/sync"]["post"]["responses"]["429"].is_object());
        assert!(document["components"]["responses"]["ErrorEnvelope"].is_object());
        assert!(document["components"]["securitySchemes"].get("queryToken").is_none());
    }

    #[test]
    fn framework_independent_handler_shape_can_be_mocked() {
        struct MockHandler;

        impl EndpointHandler for MockHandler {
            fn handle(&mut self, request: ServerRequest) -> Result<ServerResponse> {
                match request {
                    ServerRequest::ServerDescribe => {
                        Ok(ServerResponse::ServerDescription(ServerDescription {
                            service_did: crate::Did::new("did:web:svc.example").unwrap(),
                            service_type: "principal_server".to_owned(),
                            protocol_version: crate::PROTOCOL_VERSION.to_owned(),
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
                        }))
                    }
                    _ => Err(crate::Error::Protocol("mock endpoint not implemented".to_owned())),
                }
            }
        }

        let mut handler = MockHandler;
        let response = handler.handle(ServerRequest::ServerDescribe).unwrap();
        let ServerResponse::ServerDescription(description) = response else {
            panic!("unexpected response");
        };
        assert!(description.supported_operations.contains(&"cx.sync.client_sync".to_owned()));
    }
}
