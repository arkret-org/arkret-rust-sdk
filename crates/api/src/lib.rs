//! Contrix client-server API catalog and wire type exports.
//!
//! This crate is deliberately framework-free. Servers can use it to register
//! routes, clients can use it to discover operation IDs and conformance tests
//! can use the same catalog without depending on the Salvo adapter.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Protocol request/response types grouped behind the API boundary.
pub mod protocol {
    pub use contrix_core::{
        AppletActorResponse, AppletDescription, AppletPingResponse, AppletProtocolResponse,
        AppletSpaceResponse, AppletTransactionRequest, AppletTransactionResponse,
        AuthzCheckRequest, AuthzCheckResponse, AuthzInvitesResponse, BlobMetadata,
        BlobUploadMetadata, BlobUploadResponse, DeviceMessagesReceiveResponse,
        DeviceMessagesSendRequest, DeviceMessagesSendResponse, DirectoryDescription,
        DirectoryResolveHandleRequest, DirectoryResolveHandleResponse,
        DirectoryResolveOrganizationRequest, DirectoryResolveOrganizationResponse,
        DirectoryResolveSpaceRequest, DirectoryResolveSpaceResponse, DirectorySearchActorsRequest,
        DirectorySearchActorsResponse, DirectorySearchOrganizationsRequest,
        DirectorySearchOrganizationsResponse, DirectorySearchSpacesRequest,
        DirectorySearchSpacesResponse, DirectorySearchUsersResponse, EffectiveGrantsResponse,
        FederationPullOperationsResponse, FederationPushOperationsRequest,
        FederationPushOperationsResponse, FederationSpaceMembersResponse,
        FederationTransactionRequest, FederationTransactionResponse, FederationVerifyActorRequest,
        FederationVerifyActorResponse, IdentityDescription, IdentityDocumentResponse,
        IdentityLogResponse, IdentityReceiptsResponse, IdentityResolveRequest,
        IdentityResolveResponse, IndexDescription, IndexEntityResponse, IndexInboxResponse,
        IndexNotificationsResponse, IndexSearchRequest, IndexSearchResponse,
        IndexSpaceHierarchyResponse, IndexThreadResponse, KeysClaimRequest, KeysClaimResponse,
        KeysQueryRequest, KeysQueryResponse, KeysUploadRequest, KeysUploadResponse,
        MediaIceConfigRequest, MediaIceConfigResponse, ModerationReportRequest,
        ModerationReportResponse, OkResponse, PolicyCheckRequest, PolicyCheckResponse,
        PushNotifyRequest, PushNotifyResponse, PushRegisterDeviceRequest,
        PushRegisterDeviceResponse, PushUnregisterDeviceRequest, QueryRequest, QueryResponse,
        RepoCommitResponse, RepoCommitsResponse, RepoDescription, RepoOperationsRequest,
        RepoOperationsResponse, RepoSyncRequest, RepoSyncResponse, ServerDescription,
        SubmitCommitResponse, SubmitDidOperationRequest, SubmitDidOperationResponse,
        SyncBackfillResponse, SyncDescription, SyncRequest, SyncResponse, SyncSnapshotHeadResponse,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiSurface {
    Server,
    Identity,
    Repo,
    Sync,
    Federation,
    Index,
    Directory,
    Blob,
    Push,
    DeviceMessages,
    Keys,
    Authz,
    Policy,
    Media,
    Moderation,
    Mimi,
    Account,
    Admin,
    Applet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointMethod {
    Get,
    Head,
    Post,
    Put,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub operation_id: &'static str,
    pub surface: ApiSurface,
    pub method: EndpointMethod,
    pub path: &'static str,
    pub request_schema: &'static str,
    pub response_schema: &'static str,
}

impl Endpoint {
    pub fn request_body_content_type(self) -> Option<&'static str> {
        match self.method {
            EndpointMethod::Post | EndpointMethod::Put => Some("application/json"),
            EndpointMethod::Get | EndpointMethod::Head => None,
        }
    }

    pub fn response_body_content_type(self) -> Option<&'static str> {
        match self.operation_id {
            "cx.blob.head" => None,
            "cx.blob.get" => Some("application/octet-stream"),
            "cx.events.subscribe" => Some("application/x-ndjson"),
            _ => Some("application/json"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointParameterLocation {
    Path,
    Query,
    Header,
}

impl EndpointParameterLocation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointParameter {
    pub name: &'static str,
    pub location: EndpointParameterLocation,
    pub required: bool,
    pub schema: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointSchemaBinding {
    pub operation_id: &'static str,
    pub request_schema: &'static str,
    pub response_schema: &'static str,
    pub request_body_content_type: Option<&'static str>,
    pub response_body_content_type: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchedEndpoint<'a> {
    pub endpoint: &'a Endpoint,
    pub path_parameters: BTreeMap<String, String>,
}

macro_rules! endpoint {
    ($surface:ident, $operation_id:literal, $method:ident, $path:literal, $request_schema:literal, $response_schema:literal) => {
        Endpoint {
            operation_id: $operation_id,
            surface: ApiSurface::$surface,
            method: EndpointMethod::$method,
            path: $path,
            request_schema: $request_schema,
            response_schema: $response_schema,
        }
    };
}

pub const ENDPOINTS: &[Endpoint] = &[
    endpoint!(
        Server,
        "cx.server.describe",
        Get,
        "/api/v1/server/describe",
        "ServerDescribeRequest",
        "ServerDescription"
    ),
    endpoint!(
        Identity,
        "cx.identity.describe_registry",
        Get,
        "/api/v1/identity/describe",
        "IdentityDescribeRequest",
        "IdentityDescription"
    ),
    endpoint!(
        Identity,
        "cx.identity.resolve",
        Post,
        "/api/v1/identity/resolve",
        "IdentityResolveRequest",
        "IdentityResolveResponse"
    ),
    endpoint!(
        Identity,
        "cx.identity.get_document",
        Get,
        "/api/v1/identity/document",
        "IdentityDocumentQuery",
        "IdentityDocumentResponse"
    ),
    endpoint!(
        Identity,
        "cx.identity.get_log",
        Get,
        "/api/v1/identity/log",
        "IdentityLogQuery",
        "IdentityLogResponse"
    ),
    endpoint!(
        Identity,
        "cx.identity.submit_did_operation",
        Post,
        "/api/v1/identity/submit-did-operation",
        "SubmitDidOperationRequest",
        "SubmitDidOperationResponse"
    ),
    endpoint!(
        Identity,
        "cx.identity.get_receipts",
        Get,
        "/api/v1/identity/receipts",
        "IdentityReceiptsQuery",
        "IdentityReceiptsResponse"
    ),
    endpoint!(
        Repo,
        "cx.repo.describe",
        Get,
        "/api/v1/repo/describe",
        "RepoDescribeQuery",
        "RepoDescription"
    ),
    endpoint!(
        Repo,
        "cx.repo.list_commits",
        Get,
        "/api/v1/repo/commits",
        "RepoCommitsQuery",
        "RepoCommitsResponse"
    ),
    endpoint!(
        Repo,
        "cx.repo.get_commit",
        Get,
        "/api/v1/repo/commit",
        "RepoCommitQuery",
        "RepoCommitResponse"
    ),
    endpoint!(
        Repo,
        "cx.repo.get_operations",
        Post,
        "/api/v1/repo/operations",
        "RepoOperationsRequest",
        "RepoOperationsResponse"
    ),
    endpoint!(
        Repo,
        "cx.repo.sync",
        Post,
        "/api/v1/repo/sync",
        "RepoSyncRequest",
        "RepoSyncResponse"
    ),
    endpoint!(
        Repo,
        "cx.repo.submit_commit",
        Post,
        "/api/v1/repo/submit-commit",
        "Commit",
        "SubmitCommitResponse"
    ),
    // C17 (spec 2026-05-08, wire-breaking): cx.sync.client_sync → cx.sync.account
    // (path unchanged, op_id renamed); cx.sync.subscribe → cx.events.subscribe at
    // /api/v1/events/subscribe; cx.events.list + cx.sync.backfill folded into
    // cx.events.query at /api/v1/events with `direction: forward|backward`.
    endpoint!(Sync, "cx.sync.account", Post, "/api/v1/sync", "SyncRequest", "SyncResponse"),
    endpoint!(
        Sync,
        "cx.sync.describe",
        Get,
        "/api/v1/sync/describe",
        "SyncDescribeRequest",
        "SyncDescription"
    ),
    endpoint!(
        Sync,
        "cx.events.subscribe",
        Get,
        "/api/v1/events/subscribe",
        "EventsSubscribeQuery",
        "EventsSubscribeFrame"
    ),
    endpoint!(
        Sync,
        "cx.events.query",
        Get,
        "/api/v1/events",
        "EventsQueryRequest",
        "EventsQueryResponse"
    ),
    endpoint!(
        Sync,
        "cx.sync.get_snapshot_head",
        Get,
        "/api/v1/sync/snapshot-head",
        "SyncSnapshotHeadQuery",
        "SyncSnapshotHeadResponse"
    ),
    endpoint!(
        Federation,
        "cx.federation.transaction",
        Put,
        "/api/v1/federation/transactions/{txn_id}",
        "FederationTransactionRequest",
        "FederationTransactionResponse"
    ),
    endpoint!(
        Federation,
        "cx.federation.push_operations",
        Post,
        "/api/v1/federation/push-operations",
        "FederationPushOperationsRequest",
        "FederationPushOperationsResponse"
    ),
    endpoint!(
        Federation,
        "cx.federation.pull_operations",
        Get,
        "/api/v1/federation/pull-operations",
        "FederationPullOperationsQuery",
        "FederationPullOperationsResponse"
    ),
    endpoint!(
        Federation,
        "cx.federation.space_members",
        Get,
        "/api/v1/federation/space-members",
        "FederationSpaceMembersQuery",
        "FederationSpaceMembersResponse"
    ),
    endpoint!(
        Federation,
        "cx.federation.verify_actor",
        Post,
        "/api/v1/federation/verify-actor",
        "FederationVerifyActorRequest",
        "FederationVerifyActorResponse"
    ),
    endpoint!(
        Index,
        "cx.index.describe",
        Get,
        "/api/v1/index/describe",
        "IndexDescribeRequest",
        "IndexDescription"
    ),
    endpoint!(
        Index,
        "cx.index.get_entity",
        Get,
        "/api/v1/index/entity",
        "IndexEntityQuery",
        "IndexEntityResponse"
    ),
    endpoint!(
        Index,
        "cx.index.query",
        Post,
        "/api/v1/index/query",
        "QueryRequest",
        "QueryResponse"
    ),
    endpoint!(
        Index,
        "cx.index.thread",
        Get,
        "/api/v1/index/thread",
        "IndexThreadQuery",
        "IndexThreadResponse"
    ),
    endpoint!(
        Index,
        "cx.index.notifications",
        Get,
        "/api/v1/index/notifications",
        "IndexNotificationsQuery",
        "IndexNotificationsResponse"
    ),
    endpoint!(
        Index,
        "cx.index.inbox",
        Get,
        "/api/v1/index/inbox",
        "IndexInboxQuery",
        "IndexInboxResponse"
    ),
    endpoint!(
        Index,
        "cx.index.search",
        Post,
        "/api/v1/index/search",
        "IndexSearchRequest",
        "IndexSearchResponse"
    ),
    endpoint!(
        Index,
        "cx.index.space_hierarchy",
        Get,
        "/api/v1/index/space-hierarchy",
        "IndexSpaceHierarchyQuery",
        "IndexSpaceHierarchyResponse"
    ),
    endpoint!(
        Directory,
        "cx.directory.describe",
        Get,
        "/api/v1/directory/describe",
        "DirectoryDescribeRequest",
        "DirectoryDescription"
    ),
    endpoint!(
        Directory,
        "cx.directory.search_spaces",
        Post,
        "/api/v1/directory/search-spaces",
        "DirectorySearchSpacesRequest",
        "DirectorySearchSpacesResponse"
    ),
    endpoint!(
        Directory,
        "cx.directory.resolve_space",
        Post,
        "/api/v1/directory/resolve-space",
        "DirectoryResolveSpaceRequest",
        "DirectoryResolveSpaceResponse"
    ),
    endpoint!(
        Directory,
        "cx.directory.search_organizations",
        Post,
        "/api/v1/directory/search-organizations",
        "DirectorySearchOrganizationsRequest",
        "DirectorySearchOrganizationsResponse"
    ),
    endpoint!(
        Directory,
        "cx.directory.resolve_organization",
        Post,
        "/api/v1/directory/resolve-organization",
        "DirectoryResolveOrganizationRequest",
        "DirectoryResolveOrganizationResponse"
    ),
    endpoint!(
        Directory,
        "cx.directory.search_actors",
        Post,
        "/api/v1/directory/search-actors",
        "DirectorySearchActorsRequest",
        "DirectorySearchActorsResponse"
    ),
    endpoint!(
        Directory,
        "cx.directory.search_users",
        Get,
        "/api/v1/directory/search-users",
        "DirectorySearchUsersQuery",
        "DirectorySearchUsersResponse"
    ),
    endpoint!(
        Directory,
        "cx.directory.resolve_handle",
        Post,
        "/api/v1/directory/resolve-handle",
        "DirectoryResolveHandleRequest",
        "DirectoryResolveHandleResponse"
    ),
    endpoint!(
        Directory,
        "cx.directory.private_contact_discovery",
        Post,
        "/api/v1/directory/private-contact-discovery",
        "PrivateContactDiscoveryRequest",
        "PrivateContactDiscoveryResponse"
    ),
    endpoint!(
        Blob,
        "cx.blob.upload",
        Post,
        "/api/v1/blob/upload",
        "BlobUploadMetadata",
        "BlobUploadResponse"
    ),
    endpoint!(
        Blob,
        "cx.blob.head",
        Head,
        "/api/v1/blob/get",
        "BlobGetQuery",
        "BlobMetadataHeaders"
    ),
    endpoint!(Blob, "cx.blob.get", Get, "/api/v1/blob/get", "BlobGetQuery", "BinaryBlobBody"),
    endpoint!(
        Push,
        "cx.push.register_device",
        Post,
        "/api/v1/push/register-device",
        "PushRegisterDeviceRequest",
        "PushRegisterDeviceResponse"
    ),
    endpoint!(
        Push,
        "cx.push.unregister_device",
        Post,
        "/api/v1/push/unregister-device",
        "PushUnregisterDeviceRequest",
        "OkResponse"
    ),
    endpoint!(
        Push,
        "cx.push.notify",
        Post,
        "/api/v1/push/notify",
        "PushNotifyRequest",
        "PushNotifyResponse"
    ),
    endpoint!(
        DeviceMessages,
        "cx.device_messages.put",
        Post,
        "/api/v1/device_messages",
        "DeviceMessagesSendRequest",
        "DeviceMessagesSendResponse"
    ),
    endpoint!(
        DeviceMessages,
        "cx.device_messages.get",
        Get,
        "/api/v1/device_messages",
        "DeviceMessagesGetQuery",
        "DeviceMessagesReceiveResponse"
    ),
    endpoint!(
        Keys,
        "cx.keys.upload",
        Post,
        "/api/v1/keys/upload",
        "KeysUploadRequest",
        "KeysUploadResponse"
    ),
    endpoint!(
        Keys,
        "cx.keys.query",
        Post,
        "/api/v1/keys/query",
        "KeysQueryRequest",
        "KeysQueryResponse"
    ),
    endpoint!(
        Keys,
        "cx.keys.claim",
        Post,
        "/api/v1/keys/claim",
        "KeysClaimRequest",
        "KeysClaimResponse"
    ),
    endpoint!(
        Keys,
        "cx.keys.keypackages.upload",
        Post,
        "/api/v1/keys/keypackages/upload",
        "KeyPackagesUploadRequest",
        "OkResponse"
    ),
    endpoint!(
        Keys,
        "cx.keys.keypackages.claim",
        Post,
        "/api/v1/keys/keypackages/claim",
        "KeyPackagesClaimRequest",
        "KeyPackagesClaimResponse"
    ),
    endpoint!(
        Keys,
        "cx.keys.keypackages.consume",
        Post,
        "/api/v1/keys/keypackages/consume",
        "KeyPackagesConsumeRequest",
        "OkResponse"
    ),
    endpoint!(
        Keys,
        "cx.keys.keypackages.revoke",
        Post,
        "/api/v1/keys/keypackages/revoke",
        "KeyPackagesRevokeRequest",
        "OkResponse"
    ),
    endpoint!(
        Authz,
        "cx.authz.get_effective_grants",
        Get,
        "/api/v1/authz/effective-grants",
        "AuthzEffectiveGrantsQuery",
        "EffectiveGrantsResponse"
    ),
    endpoint!(
        Authz,
        "cx.authz.get_invites",
        Get,
        "/api/v1/authz/invites",
        "AuthzInvitesQuery",
        "AuthzInvitesResponse"
    ),
    endpoint!(
        Authz,
        "cx.authz.check",
        Post,
        "/api/v1/authz/check",
        "AuthzCheckRequest",
        "AuthzCheckResponse"
    ),
    endpoint!(
        Policy,
        "cx.policy.check",
        Post,
        "/contrix/v1/check",
        "PolicyCheckRequest",
        "PolicyCheckResponse"
    ),
    endpoint!(
        Media,
        "cx.media.ice_config",
        Post,
        "/contrix/v1/ice-config",
        "MediaIceConfigRequest",
        "MediaIceConfigResponse"
    ),
    endpoint!(
        Moderation,
        "cx.moderation.report",
        Post,
        "/api/v1/moderation/report",
        "ModerationReportRequest",
        "ModerationReportResponse"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.provider_directory",
        Get,
        "/api/v1/mimi/provider-directory",
        "MimiProviderDirectoryRequest",
        "JsonValue"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.key_material",
        Post,
        "/api/v1/mimi/key-material",
        "MimiKeyMaterialRequest",
        "JsonValue"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.flow_update",
        Put,
        "/api/v1/mimi/flows/{flow_id}/update",
        "MimiFlowUpdateRequest",
        "JsonValue"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.notify",
        Post,
        "/api/v1/mimi/flows/{flow_id}/notify",
        "MimiNotifyRequest",
        "JsonValue"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.submit_message",
        Post,
        "/api/v1/mimi/flows/{flow_id}/messages",
        "MimiSubmitMessageRequest",
        "JsonValue"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.group_info",
        Get,
        "/api/v1/mimi/flows/{flow_id}/group-info",
        "MimiGroupInfoQuery",
        "JsonValue"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.request_consent",
        Post,
        "/api/v1/mimi/consent/request",
        "MimiConsentRequest",
        "JsonValue"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.update_consent",
        Post,
        "/api/v1/mimi/consent/update",
        "MimiConsentUpdateRequest",
        "JsonValue"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.identifier_query",
        Post,
        "/api/v1/mimi/identifiers/query",
        "MimiIdentifierQueryRequest",
        "JsonValue"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.report_abuse",
        Post,
        "/api/v1/mimi/report-abuse",
        "MimiReportAbuseRequest",
        "OkResponse"
    ),
    endpoint!(
        Mimi,
        "cx.mimi.proxy_download",
        Post,
        "/api/v1/mimi/proxy-download",
        "MimiProxyDownloadRequest",
        "JsonValue"
    ),
    endpoint!(
        Account,
        "cx.account.issue_session_grant",
        Post,
        "/api/v1/auth/account/session-grants",
        "AccountSessionGrantRequest",
        "AccountSessionGrantResponse"
    ),
    endpoint!(
        Account,
        "cx.account.device_pair",
        Post,
        "/api/v1/auth/account/device-pair",
        "AccountDevicePairRequest",
        "AccountDevicePairResponse"
    ),
    endpoint!(
        Account,
        "cx.account.oidc_callback",
        Post,
        "/api/v1/auth/account/oidc/callback",
        "AccountOidcCallbackRequest",
        "AccountOidcCallbackResponse"
    ),
    endpoint!(
        Admin,
        "cx.admin.get_server_status",
        Get,
        "/api/v1/admin/server/status",
        "AdminServerStatusQuery",
        "JsonValue"
    ),
    endpoint!(
        Admin,
        "cx.admin.update_account_status",
        Post,
        "/api/v1/admin/accounts/{account_id}/status",
        "AdminAccountStatusRequest",
        "OkResponse"
    ),
    endpoint!(
        Admin,
        "cx.admin.revoke_device",
        Post,
        "/api/v1/admin/devices/{device_id}/revoke",
        "AdminRevokeDeviceRequest",
        "OkResponse"
    ),
    endpoint!(
        Admin,
        "cx.admin.get_moderation_queue",
        Get,
        "/api/v1/admin/moderation/queue",
        "AdminModerationQueueQuery",
        "JsonValue"
    ),
    endpoint!(
        Applet,
        "cx.applet.ping",
        Get,
        "/api/v1/applet/ping",
        "AppletPingRequest",
        "AppletPingResponse"
    ),
    endpoint!(
        Applet,
        "cx.applet.describe",
        Get,
        "/api/v1/applet/describe",
        "AppletDescribeRequest",
        "AppletDescription"
    ),
    endpoint!(
        Applet,
        "cx.applet.transaction",
        Post,
        "/api/v1/applet/transactions",
        "AppletTransactionRequest",
        "AppletTransactionResponse"
    ),
    endpoint!(
        Applet,
        "cx.applet.query_actor",
        Get,
        "/api/v1/applet/actors/{actor_id}",
        "AppletActorPath",
        "AppletActorResponse"
    ),
    endpoint!(
        Applet,
        "cx.applet.query_space",
        Get,
        "/api/v1/applet/spaces/{space_id_or_alias}",
        "AppletSpacePath",
        "AppletSpaceResponse"
    ),
    endpoint!(
        Applet,
        "cx.applet.protocol_metadata",
        Get,
        "/api/v1/applet/protocols/{protocol}",
        "AppletProtocolPath",
        "AppletProtocolResponse"
    ),
    endpoint!(
        Applet,
        "cx.applet.third_party_users",
        Get,
        "/api/v1/applet/third_party/users",
        "AppletThirdPartyUsersRequest",
        "JsonValue"
    ),
    endpoint!(
        Applet,
        "cx.applet.third_party_locations",
        Get,
        "/api/v1/applet/third_party/locations",
        "AppletThirdPartyLocationsRequest",
        "JsonValue"
    ),
];

pub fn endpoints() -> &'static [Endpoint] {
    ENDPOINTS
}

pub fn endpoint_by_operation(operation_id: &str) -> Option<&'static Endpoint> {
    ENDPOINTS.iter().find(|endpoint| endpoint.operation_id == operation_id)
}

pub fn endpoints_for_surface(surface: ApiSurface) -> impl Iterator<Item = &'static Endpoint> {
    ENDPOINTS.iter().filter(move |endpoint| endpoint.surface == surface)
}

pub fn endpoint_schema_bindings() -> Vec<EndpointSchemaBinding> {
    endpoints().iter().copied().map(endpoint_schema_binding).collect()
}

pub fn endpoint_schema_binding(endpoint: Endpoint) -> EndpointSchemaBinding {
    EndpointSchemaBinding {
        operation_id: endpoint.operation_id,
        request_schema: endpoint.request_schema,
        response_schema: endpoint.response_schema,
        request_body_content_type: endpoint.request_body_content_type(),
        response_body_content_type: endpoint.response_body_content_type(),
    }
}

pub fn endpoint_parameters(endpoint: Endpoint) -> Vec<EndpointParameter> {
    let mut parameters = path_parameters(endpoint.path);
    parameters.extend(query_parameters(endpoint.operation_id));
    parameters.extend(header_parameters(endpoint.operation_id));
    parameters.push(EndpointParameter {
        name: "X-Contrix-Request-Id",
        location: EndpointParameterLocation::Header,
        required: false,
        schema: "String",
    });
    parameters.push(EndpointParameter {
        name: "Traceparent",
        location: EndpointParameterLocation::Header,
        required: false,
        schema: "String",
    });
    parameters
}

pub fn match_endpoint(method: EndpointMethod, path: &str) -> Option<MatchedEndpoint<'static>> {
    endpoints().iter().filter(|endpoint| endpoint.method == method).find_map(|endpoint| {
        match_path_template(endpoint.path, path)
            .map(|path_parameters| MatchedEndpoint { endpoint, path_parameters })
    })
}

fn path_parameters(path: &'static str) -> Vec<EndpointParameter> {
    path.split('/')
        .filter_map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                Some(EndpointParameter {
                    name: &segment[1..segment.len() - 1],
                    location: EndpointParameterLocation::Path,
                    required: true,
                    schema: "String",
                })
            } else {
                None
            }
        })
        .collect()
}

fn query_parameters(operation_id: &str) -> Vec<EndpointParameter> {
    let query: &[(&str, bool, &str)] = match operation_id {
        "cx.identity.get_document" => &[("did", true, "Did"), ("version", false, "String")],
        "cx.identity.get_log" => {
            &[("did", true, "Did"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.identity.get_receipts" => &[("did", true, "Did"), ("head", true, "Hash")],
        "cx.repo.describe" => &[("repo_id", false, "Did")],
        "cx.repo.list_commits" => {
            &[("repo_id", true, "Did"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.repo.get_commit" => &[("commit_id", true, "String"), ("repo_id", false, "Did")],
        // C17: cx.events.subscribe — selector via `spaces[]` / `actors[]` repeated query args;
        // include_history=true flips after `catchup_complete` frame to live stream.
        "cx.events.subscribe" => &[
            ("spaces", false, "SpaceId"),
            ("actors", false, "Did"),
            ("from", false, "String"),
            ("include_history", false, "Bool"),
        ],
        // C17: cx.events.query — folds cx.events.list + cx.sync.backfill via `direction`.
        "cx.events.query" => &[
            ("spaces", false, "SpaceId"),
            ("actors", false, "Did"),
            ("from", false, "String"),
            ("until", false, "String"),
            ("direction", false, "String"),
            ("limit", false, "Limit"),
        ],
        "cx.sync.get_snapshot_head" => &[("space_id", true, "SpaceId")],
        "cx.federation.pull_operations" => &[
            ("space_id", true, "SpaceId"),
            ("after_cursor", false, "String"),
            ("limit", false, "Limit"),
        ],
        "cx.federation.space_members" => {
            &[("space_id", true, "SpaceId"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.index.get_entity" => &[
            ("entity_id", true, "String"),
            ("space_id", false, "SpaceId"),
            ("at", false, "String"),
        ],
        "cx.index.thread" => {
            &[("topic_id", true, "String"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.index.notifications" => {
            &[("cursor", false, "String"), ("state", false, "String"), ("limit", false, "Limit")]
        }
        "cx.index.inbox" => {
            &[("scope", false, "String"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
        "cx.index.space_hierarchy" => &[
            ("space_id", true, "SpaceId"),
            ("depth", false, "Limit"),
            ("include_unconfirmed", false, "Bool"),
        ],
        "cx.directory.search_users" => {
            &[("q", true, "String"), ("space_id", false, "SpaceId"), ("limit", false, "Limit")]
        }
        "cx.blob.head" | "cx.blob.get" => &[("blob_ref", true, "BlobRef")],
        "cx.device_messages.get" => &[("from", false, "String"), ("limit", false, "Limit")],
        "cx.authz.get_effective_grants" => {
            &[("space_id", true, "SpaceId"), ("subject", true, "Did"), ("at", false, "String")]
        }
        "cx.authz.get_invites" => {
            &[("subject", true, "Did"), ("space_id", false, "SpaceId"), ("cursor", false, "String")]
        }
        _ => &[],
    };

    query
        .iter()
        .map(|(name, required, schema)| EndpointParameter {
            name,
            location: EndpointParameterLocation::Query,
            required: *required,
            schema,
        })
        .collect()
}

fn header_parameters(operation_id: &str) -> Vec<EndpointParameter> {
    let headers: &[(&str, bool, &str)] = match operation_id {
        "cx.index.query" => &[("X-Contrix-Wait-For", false, "String")],
        "cx.blob.upload" => &[
            ("X-Contrix-Blob-Metadata", false, "BlobUploadMetadata"),
            ("Content-Type", false, "String"),
            ("Content-Disposition", false, "String"),
            ("Digest", false, "Hash"),
        ],
        "cx.blob.get" => &[("Range", false, "String")],
        "cx.device_messages.put" | "cx.applet.transaction" => {
            &[("Idempotency-Key", true, "String")]
        }
        _ => &[],
    };

    headers
        .iter()
        .map(|(name, required, schema)| EndpointParameter {
            name,
            location: EndpointParameterLocation::Header,
            required: *required,
            schema,
        })
        .collect()
}

fn match_path_template(template: &str, path: &str) -> Option<BTreeMap<String, String>> {
    let template_segments = template.trim_matches('/').split('/');
    let path_segments = path.trim_matches('/').split('/');
    let mut parameters = BTreeMap::new();

    for (template_segment, path_segment) in template_segments.zip(path_segments) {
        if template_segment.starts_with('{') && template_segment.ends_with('}') {
            let name = &template_segment[1..template_segment.len() - 1];
            parameters.insert(name.to_owned(), path_segment.to_owned());
        } else if template_segment != path_segment {
            return None;
        }
    }

    if template.trim_matches('/').split('/').count() != path.trim_matches('/').split('/').count() {
        return None;
    }

    Some(parameters)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn operation_ids_are_unique() {
        let mut ids = BTreeSet::new();
        for endpoint in endpoints() {
            assert!(ids.insert(endpoint.operation_id), "duplicate {}", endpoint.operation_id);
        }
    }

    #[test]
    fn catalog_covers_protocol_surfaces() {
        for surface in [
            ApiSurface::Server,
            ApiSurface::Identity,
            ApiSurface::Repo,
            ApiSurface::Sync,
            ApiSurface::Federation,
            ApiSurface::Index,
            ApiSurface::Directory,
            ApiSurface::Blob,
            ApiSurface::Push,
            ApiSurface::DeviceMessages,
            ApiSurface::Keys,
            ApiSurface::Authz,
            ApiSurface::Policy,
            ApiSurface::Media,
            ApiSurface::Moderation,
            ApiSurface::Mimi,
            ApiSurface::Account,
            ApiSurface::Admin,
            ApiSurface::Applet,
        ] {
            assert!(endpoints_for_surface(surface).next().is_some(), "{surface:?}");
        }
    }

    #[test]
    fn matcher_routes_post_applet_transactions() {
        let matched = match_endpoint(EndpointMethod::Post, "/api/v1/applet/transactions").unwrap();
        assert_eq!(matched.endpoint.operation_id, "cx.applet.transaction");
        assert!(matched.path_parameters.is_empty());
    }

    #[test]
    fn endpoint_parameters_include_common_tracing_headers() {
        let endpoint = endpoint_by_operation("cx.blob.upload").unwrap();
        let parameters = endpoint_parameters(*endpoint);
        assert!(parameters.iter().any(|parameter| parameter.name == "X-Contrix-Request-Id"));
        assert!(parameters.iter().any(|parameter| parameter.name == "Traceparent"));
        assert!(parameters.iter().any(|parameter| parameter.name == "X-Contrix-Blob-Metadata"));
    }
}
