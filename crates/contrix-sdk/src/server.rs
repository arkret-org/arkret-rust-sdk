//! Server-side protocol endpoint registry.
//!
//! This module is intentionally framework-free. HTTP servers can use these
//! contracts to keep route registration and advertised operation IDs aligned
//! with the protocol without pulling a web stack into the SDK.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointParameter {
    pub name: &'static str,
    pub location: EndpointParameterLocation,
    pub required: bool,
    pub schema: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointSchemaBinding {
    pub operation_id: &'static str,
    pub request_schema: &'static str,
    pub response_schema: &'static str,
    pub request_body_content_type: Option<&'static str>,
    pub response_body_content_type: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpAdapterRequest {
    pub method: EndpointMethod,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpAdapterResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchedEndpoint<'a> {
    pub contract: &'a EndpointContract,
    pub path_parameters: BTreeMap<String, String>,
}

pub trait TowerLikeEndpointService {
    type Request;
    type Response;

    fn call(&mut self, request: Self::Request) -> Result<Self::Response>;
}

impl<F> TowerLikeEndpointService for F
where
    F: FnMut(HttpAdapterRequest) -> Result<HttpAdapterResponse>,
{
    type Request = HttpAdapterRequest;
    type Response = HttpAdapterResponse;

    fn call(&mut self, request: Self::Request) -> Result<Self::Response> {
        self(request)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProtocolGoldenVector {
    pub name: String,
    pub profile: String,
    pub input: Value,
    pub expected: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireConformanceVector {
    pub name: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub body: Value,
    pub expected_status: u16,
    pub expected_errcode: String,
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

pub fn endpoint_schema_bindings() -> Vec<EndpointSchemaBinding> {
    endpoint_contracts().iter().map(endpoint_schema_binding).collect()
}

pub fn endpoint_schema_binding(endpoint: &EndpointContract) -> EndpointSchemaBinding {
    let (request_schema, response_schema) = match endpoint.operation_id {
        "cx.server.describe" => ("ServerDescribeRequest", "ServerDescription"),
        "cx.identity.describe_registry" => ("IdentityDescribeRequest", "IdentityDescription"),
        "cx.identity.resolve" => ("IdentityResolveRequest", "IdentityResolveResponse"),
        "cx.identity.get_document" => ("IdentityDocumentQuery", "IdentityDocumentResponse"),
        "cx.identity.get_log" => ("IdentityLogQuery", "IdentityLogResponse"),
        "cx.identity.submit_did_operation" => {
            ("SubmitDidOperationRequest", "SubmitDidOperationResponse")
        }
        "cx.identity.get_receipts" => ("IdentityReceiptsQuery", "IdentityReceiptsResponse"),
        "cx.repo.describe" => ("RepoDescribeQuery", "RepoDescription"),
        "cx.repo.list_commits" => ("RepoCommitsQuery", "RepoCommitsResponse"),
        "cx.repo.get_commit" => ("RepoCommitQuery", "RepoCommitResponse"),
        "cx.repo.get_operations" => ("RepoOperationsRequest", "RepoOperationsResponse"),
        "cx.repo.sync" => ("RepoSyncRequest", "RepoSyncResponse"),
        "cx.repo.submit_commit" => ("Commit", "SubmitCommitResponse"),
        "cx.sync.client_sync" => ("SyncRequest", "SyncResponse"),
        "cx.sync.describe" => ("SyncDescribeRequest", "SyncDescription"),
        "cx.sync.subscribe" => ("SyncSubscribeQuery", "SyncSubscribeFrame"),
        "cx.sync.backfill" => ("SyncBackfillQuery", "SyncBackfillResponse"),
        "cx.sync.get_snapshot_head" => ("SyncSnapshotHeadQuery", "SyncSnapshotHeadResponse"),
        "cx.federation.transaction" => {
            ("FederationTransactionRequest", "FederationTransactionResponse")
        }
        "cx.federation.push_operations" => {
            ("FederationPushOperationsRequest", "FederationPushOperationsResponse")
        }
        "cx.federation.pull_operations" => {
            ("FederationPullOperationsQuery", "FederationPullOperationsResponse")
        }
        "cx.federation.space_members" => {
            ("FederationSpaceMembersQuery", "FederationSpaceMembersResponse")
        }
        "cx.federation.verify_actor" => {
            ("FederationVerifyActorRequest", "FederationVerifyActorResponse")
        }
        "cx.index.describe" => ("IndexDescribeRequest", "IndexDescription"),
        "cx.index.get_entity" => ("IndexEntityQuery", "IndexEntityResponse"),
        "cx.index.query" => ("QueryRequest", "QueryResponse"),
        "cx.index.thread" => ("IndexThreadQuery", "IndexThreadResponse"),
        "cx.index.notifications" => ("IndexNotificationsQuery", "IndexNotificationsResponse"),
        "cx.index.inbox" => ("IndexInboxQuery", "IndexInboxResponse"),
        "cx.index.search" => ("IndexSearchRequest", "IndexSearchResponse"),
        "cx.index.space_hierarchy" => ("IndexSpaceHierarchyQuery", "IndexSpaceHierarchyResponse"),
        "cx.directory.describe" => ("DirectoryDescribeRequest", "DirectoryDescription"),
        "cx.directory.search_spaces" => {
            ("DirectorySearchSpacesRequest", "DirectorySearchSpacesResponse")
        }
        "cx.directory.resolve_space" => {
            ("DirectoryResolveSpaceRequest", "DirectoryResolveSpaceResponse")
        }
        "cx.directory.search_organizations" => {
            ("DirectorySearchOrganizationsRequest", "DirectorySearchOrganizationsResponse")
        }
        "cx.directory.resolve_organization" => {
            ("DirectoryResolveOrganizationRequest", "DirectoryResolveOrganizationResponse")
        }
        "cx.directory.search_actors" => {
            ("DirectorySearchActorsRequest", "DirectorySearchActorsResponse")
        }
        "cx.directory.search_users" => {
            ("DirectorySearchUsersQuery", "DirectorySearchUsersResponse")
        }
        "cx.directory.resolve_handle" => {
            ("DirectoryResolveHandleRequest", "DirectoryResolveHandleResponse")
        }
        "cx.blob.upload" => ("BlobUploadMetadata", "BlobUploadResponse"),
        "cx.blob.head" => ("BlobGetQuery", "BlobMetadataHeaders"),
        "cx.blob.get" => ("BlobGetQuery", "BinaryBlobBody"),
        "cx.push.register_device" => ("PushRegisterDeviceRequest", "PushRegisterDeviceResponse"),
        "cx.push.unregister_device" => ("PushUnregisterDeviceRequest", "OkResponse"),
        "cx.push.notify" => ("PushNotifyRequest", "PushNotifyResponse"),
        "cx.device_messages.put" => ("DeviceMessagesSendRequest", "DeviceMessagesSendResponse"),
        "cx.device_messages.get" => ("DeviceMessagesGetQuery", "DeviceMessagesReceiveResponse"),
        "cx.keys.upload" => ("KeysUploadRequest", "KeysUploadResponse"),
        "cx.keys.query" => ("KeysQueryRequest", "KeysQueryResponse"),
        "cx.keys.claim" => ("KeysClaimRequest", "KeysClaimResponse"),
        "cx.authz.get_effective_grants" => ("AuthzEffectiveGrantsQuery", "EffectiveGrantsResponse"),
        "cx.authz.get_invites" => ("AuthzInvitesQuery", "AuthzInvitesResponse"),
        "cx.authz.check" => ("AuthzCheckRequest", "AuthzCheckResponse"),
        "cx.policy.check" => ("PolicyCheckRequest", "PolicyCheckResponse"),
        "cx.media.ice_config" => ("MediaIceConfigRequest", "MediaIceConfigResponse"),
        "cx.moderation.report" => ("ModerationReportRequest", "ModerationReportResponse"),
        "cx.applet.ping" => ("AppletPingRequest", "AppletPingResponse"),
        "cx.applet.describe" => ("AppletDescribeRequest", "AppletDescription"),
        "cx.applet.transaction" => ("AppletTransactionRequest", "AppletTransactionResponse"),
        "cx.applet.query_actor" => ("AppletActorPath", "AppletActorResponse"),
        "cx.applet.query_space" => ("AppletSpacePath", "AppletSpaceResponse"),
        "cx.applet.protocol_metadata" => ("AppletProtocolPath", "AppletProtocolResponse"),
        "cx.applet.third_party_users" => ("AppletThirdPartyUsersRequest", "JsonValue"),
        "cx.applet.third_party_locations" => ("AppletThirdPartyLocationsRequest", "JsonValue"),
        _ => ("JsonValue", "JsonValue"),
    };

    EndpointSchemaBinding {
        operation_id: endpoint.operation_id,
        request_schema,
        response_schema,
        request_body_content_type: request_body_content_type(endpoint),
        response_body_content_type: response_body_content_type(endpoint),
    }
}

pub fn endpoint_parameters(endpoint: &EndpointContract) -> Vec<EndpointParameter> {
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
    endpoint_contracts().iter().filter(|endpoint| endpoint.method == method).find_map(|endpoint| {
        match_path_template(endpoint.path, path)
            .map(|path_parameters| MatchedEndpoint { contract: endpoint, path_parameters })
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
            return Err(crate::Error::Protocol(
                "authentication material must be sent in headers, not query parameters".to_owned(),
            ));
        }
    }
    Ok(())
}

pub fn protocol_golden_vectors() -> Vec<ProtocolGoldenVector> {
    vec![
        ProtocolGoldenVector {
            name: "did_uuid_v4_layout".to_owned(),
            profile: "cx.conformance.identifiers.v1".to_owned(),
            input: json!({"did": "did:uuid:550e8400-e29b-41d4-a716-446655440000"}),
            expected: json!({"valid": true, "method": "uuid"}),
        },
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
            name: "stale_cursor_rejected".to_owned(),
            method: "GET".to_owned(),
            path: "/api/v1/federation/pull-operations".to_owned(),
            query: BTreeMap::from([
                ("space_id".to_owned(), "cx:space:01JS0SP000000000000000000".to_owned()),
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
            name: "missing_auth_rejected".to_owned(),
            method: "POST".to_owned(),
            path: "/api/v1/repo/submit-commit".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: json!({}),
            expected_status: 401,
            expected_errcode: "cx.error.unauthorized".to_owned(),
        },
    ]
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

fn request_body_content_type(endpoint: &EndpointContract) -> Option<&'static str> {
    match endpoint.method {
        EndpointMethod::Post | EndpointMethod::Put => Some("application/json"),
        EndpointMethod::Get | EndpointMethod::Head => None,
    }
}

fn response_body_content_type(endpoint: &EndpointContract) -> Option<&'static str> {
    match endpoint.operation_id {
        "cx.blob.head" => None,
        "cx.blob.get" => Some("application/octet-stream"),
        "cx.sync.subscribe" => Some("application/x-ndjson"),
        _ => Some("application/json"),
    }
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
        "cx.sync.subscribe" => &[("space_id", true, "SpaceId"), ("cursor", false, "String")],
        "cx.sync.backfill" => {
            &[("space_id", true, "SpaceId"), ("cursor", false, "String"), ("limit", false, "Limit")]
        }
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

pub fn openapi_document() -> Value {
    let mut paths = serde_json::Map::new();
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
                "deviceProof": { "type": "apiKey", "in": "header", "name": "X-Contrix-Device-Proof" },
                "serviceSignature": { "type": "apiKey", "in": "header", "name": "Signature" }
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
            | "cx.index.describe"
            | "cx.directory.describe"
            | "cx.applet.ping"
            | "cx.applet.describe"
    ) {
        json!([{}])
    } else if operation_id.starts_with("cx.federation.") {
        json!([{ "serviceSignature": [] }])
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
        "410": { "$ref": "#/components/responses/StaleCursorError" },
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
        "Commit",
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

    let mut schemas = Map::new();
    for name in schema_names {
        schemas.insert(name.to_owned(), generic_schema(name));
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
                "operation_id": { "type": "string" },
                "commit_id": { "type": "string" }
            },
            "additionalProperties": false
        }),
    );

    Value::Object(schemas)
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
        "StaleCursorError": error_response("Cursor is expired or no longer replayable", "StaleCursorError"),
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
                "protocol_version": crate::PROTOCOL_VERSION,
                "supported_operations": ["cx.server.describe", "cx.sync.client_sync"]
            }
        },
        "SyncRequest": {
            "summary": "Incremental sync request",
            "value": {
                "since": "cx:cursor:sync:01JS0SP000000000000000000",
                "space_ids": ["cx:space:01JS0SP000000000000000000"],
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
                "space_id": "cx:space:01JS0SP000000000000000000",
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
        "StaleCursorError": {
            "value": { "errcode": "cx.error.stale_cursor", "error": "Cursor is expired" }
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
        "cx.sync.client_sync" => Some("#/components/examples/SyncRequest"),
        "cx.federation.transaction" => Some("#/components/examples/FederationTransactionRequest"),
        "cx.blob.upload" => Some("#/components/examples/BlobUploadMetadata"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
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
        assert!(document["components"]["schemas"]["ErrorEnvelope"].is_object());
        assert!(document["components"]["responses"]["RateLimitedError"].is_object());
        assert!(document["components"]["securitySchemes"].get("queryToken").is_none());
    }

    #[test]
    fn openapi_document_has_schema_binding_for_every_endpoint() {
        let document = openapi_document();
        for endpoint in endpoint_contracts() {
            let binding = endpoint_schema_binding(endpoint);
            assert!(
                document["components"]["schemas"].get(binding.request_schema).is_some(),
                "{} request schema {}",
                endpoint.operation_id,
                binding.request_schema
            );
            assert!(
                document["components"]["schemas"].get(binding.response_schema).is_some(),
                "{} response schema {}",
                endpoint.operation_id,
                binding.response_schema
            );
            assert_eq!(
                document["paths"][endpoint.path][endpoint.method.as_str()]["operationId"],
                endpoint.operation_id
            );
        }
        assert!(
            document["paths"]["/api/v1/federation/transactions/{txn_id}"]["put"]["requestBody"]
                .is_object()
        );
        assert!(
            document["components"]["examples"]["FederationTransactionRequest"]["value"].is_object()
        );
    }

    #[test]
    fn endpoint_matcher_extracts_path_parameters_for_framework_adapters() {
        let matched =
            match_endpoint(EndpointMethod::Put, "/api/v1/applet/transactions/txn_123").unwrap();
        assert_eq!(matched.contract.operation_id, "cx.applet.transaction");
        assert_eq!(matched.path_parameters["txn_id"], "txn_123");
        assert!(
            match_endpoint(EndpointMethod::Get, "/api/v1/applet/transactions/txn_123").is_none()
        );
    }

    #[test]
    fn tower_like_endpoint_service_can_wrap_framework_closure() {
        let mut service = |request: HttpAdapterRequest| {
            let matched = match_endpoint(request.method, &request.path)
                .ok_or_else(|| crate::Error::Protocol("no route".to_owned()))?;
            Ok(HttpAdapterResponse {
                status: 200,
                headers: BTreeMap::from([(
                    "X-Contrix-Operation-Id".to_owned(),
                    matched.contract.operation_id.to_owned(),
                )]),
                body: Vec::new(),
            })
        };

        let response = service
            .call(HttpAdapterRequest {
                method: EndpointMethod::Get,
                path: "/api/v1/server/describe".to_owned(),
                query: BTreeMap::new(),
                headers: BTreeMap::new(),
                body: Vec::new(),
            })
            .unwrap();
        assert_eq!(response.headers["X-Contrix-Operation-Id"], "cx.server.describe");
    }

    #[test]
    fn query_auth_and_wire_negative_vectors_are_available() {
        let query = BTreeMap::from([("access_token".to_owned(), "secret".to_owned())]);
        assert!(reject_query_auth(&query).is_err());

        let vectors = wire_negative_vectors();
        assert!(vectors.iter().any(|vector| vector.name == "query_auth_rejected"));
        assert!(vectors.iter().any(|vector| vector.expected_errcode == "cx.error.bad_digest"));

        let golden = protocol_golden_vectors();
        assert!(golden.iter().any(|vector| vector.profile == "cx.conformance.digest.v1"));
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
        assert!(description.supported_operations.contains(&"cx.sync.client_sync".