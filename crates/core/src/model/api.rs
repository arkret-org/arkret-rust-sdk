use super::*;

/// Verification state for a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeviceVerificationState {
    /// Device has not been verified.
    Unverified,
    /// Verification is in progress.
    VerificationStarted,
    /// Device has been verified.
    Verified,
    /// Device is blocked.
    Blocked,
    /// Device was deleted locally.
    Deleted,
    /// Verification failed due to mismatch.
    VerificationFailed,
    /// Verification was cancelled before completion.
    VerificationCancelled,
    /// Verification expired before completion.
    VerificationExpired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ServerDescription {
    pub service_did: Did,
    pub service_type: String,
    pub protocol_version: String,
    #[serde(default)]
    pub supported_profiles: Vec<String>,
    #[serde(default)]
    pub supported_features: Vec<String>,
    #[serde(default)]
    pub supported_operations: Vec<String>,
    #[serde(default)]
    pub supported_bindings: Vec<Value>,
    #[serde(default)]
    pub supported_reducer_profiles: Vec<String>,
    #[serde(default)]
    pub supported_schema_profiles: Vec<String>,
    #[serde(default)]
    pub auth_metadata: Value,
    #[serde(default)]
    pub limits: Value,
    /// Current causal frontier exposed by the service. Clients SHOULD
    /// use this to detect a service that has fallen behind a known
    /// snapshot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frontier: Vec<EventId>,
    /// Frontier of the most recent snapshot the service can serve from
    /// (empty means snapshot-assisted resolution is unavailable).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snapshot_frontier: Vec<EventId>,
    /// Active reducer profile (e.g. `cx.reducer.v1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reducer_profile: Option<String>,
    /// Wall-clock time of the most recent successful state
    /// materialization. A stale `last_materialized_at` paired with a
    /// fresh `frontier` indicates the projection layer is degraded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_materialized_at: Option<DateTime<Utc>>,
}

impl ServerDescription {
    pub fn supports_contrix_v1(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ErrorEnvelope {
    pub errcode: String,
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl fmt::Display for ErrorEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.errcode, self.error)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityDescription {
    pub service_did: Did,
    pub registry_mode: String,
    #[serde(default)]
    pub supported_receipts: Vec<String>,
    pub protocol_version: String,
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityResolveRequest {
    pub did: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityResolveResponse {
    pub did_document: DidDocumentRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub method_evidence: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DidDocumentRef {
    pub did: Did,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub document: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityDocumentResponse {
    pub did_document: DidDocumentRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_event_hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityLogResponse {
    #[serde(default)]
    pub events: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SubmitDidOperationRequest {
    pub did: Did,
    pub seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event_hash: Option<Hash>,
    pub patch: Value,
    #[serde(default)]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SubmitDidOperationResponse {
    pub status: String,
    pub head_event_hash: Hash,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct IdentityReceiptsResponse {
    #[serde(default)]
    pub receipts: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_met: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub space_ids: Vec<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncResponse {
    pub next_batch: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub spaces: BTreeMap<SpaceId, SyncSpace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_device: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub device_lists: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub account_data: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presence: Vec<Value>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub partial: bool,
}

impl SyncResponse {
    /// Native Contrix space map.
    pub fn effective_spaces(&self) -> &BTreeMap<SpaceId, SyncSpace> {
        &self.spaces
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncSpace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<SyncTimeline>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state: Vec<Event>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub summary: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ephemeral: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub unread: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncTimeline {
    pub events: Vec<Event>,
    pub limited: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_batch: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncDescription {
    pub service_did: Did,
    #[serde(default)]
    pub supported_sync_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub limits: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncBackfillResponse {
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SyncSnapshotHeadResponse {
    pub snapshot_ref: String,
    pub state_hash: Hash,
    pub frontier: String,
    pub signature: Value,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthzCheckRequest {
    pub actor_id: Did,
    pub action: String,
    pub resource: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(default)]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthzCheckResponse {
    pub decision: AuthzDecision,
    #[serde(default)]
    pub matched_grants: Vec<GrantId>,
    #[serde(default)]
    pub applied_constraints: Vec<Value>,
    #[serde(default)]
    pub policy_results: Vec<Value>,
    #[serde(default)]
    pub missing_proofs: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_valid_until: Option<DateTime<Utc>>,
}

pub type Capability = CapabilityGrant;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EffectiveGrantsResponse {
    #[serde(default)]
    pub grants: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_hash: Option<Hash>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AuthzInvitesResponse {
    #[serde(default)]
    pub invites: Vec<Invite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationTransactionRequest {
    pub origin: Did,
    pub destination: Did,
    pub service_binding_ref: String,
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationTransactionResponse {
    pub ok: bool,
    #[serde(default)]
    pub accepted: Vec<OperationId>,
    #[serde(default)]
    pub rejected: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationPushOperationsRequest {
    pub origin: Did,
    pub destination: Did,
    pub space_id: SpaceId,
    pub service_binding_ref: String,
    #[serde(default)]
    pub operations: Vec<Operation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationPushOperationsResponse {
    #[serde(default)]
    pub accepted: Vec<OperationId>,
    #[serde(default)]
    pub rejected: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationPullOperationsResponse {
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationSpaceMembersResponse {
    #[serde(default)]
    pub members: Vec<MemberRef>,
    pub membership_frontier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MemberRef {
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub membership: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationVerifyActorRequest {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_payload_hash: Option<Hash>,
    pub signature: Value,
    pub purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FederationVerifyActorResponse {
    pub valid: bool,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_log_head: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct QueryResult<T> {
    pub item: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryDescription {
    pub service_did: Did,
    #[serde(default)]
    pub resource_types: Vec<String>,
    #[serde(default)]
    pub discovery_profiles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restricted_query_proof: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchSpacesRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchSpacesResponse {
    #[serde(default)]
    pub results: Vec<SpacePreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SpacePreview {
    pub space_id: SpaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveSpaceRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveSpaceResponse {
    pub space_preview: SpacePreview,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stripped_state: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_rule: Option<JoinRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via_services: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchOrganizationsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub claims: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchOrganizationsResponse {
    #[serde(default)]
    pub results: Vec<OrganizationPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OrganizationPreview {
    pub organization_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveOrganizationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveOrganizationResponse {
    pub organization_preview: OrganizationPreview,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endorsements: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchActorsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchActorsResponse {
    #[serde(default)]
    pub results: Vec<ActorPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ActorPreview {
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub preview: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectorySearchUsersResponse {
    #[serde(default)]
    pub results: Vec<ActorPreview>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveHandleRequest {
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_challenge: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DirectoryResolveHandleResponse {
    pub did: Did,
    pub handle: String,
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub claims: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BlobUploadMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Hash>,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct BlobUploadResponse {
    pub blob_ref: BlobRef,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub sha256: Hash,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub upload_receipt: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRegisterDeviceRequest {
    pub device_id: DeviceId,
    pub push_gateway: String,
    pub push_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRegisterDeviceResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushUnregisterDeviceRequest {
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct OkResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushNotifyRequest {
    pub notification: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushNotifyResponse {
    #[serde(default)]
    pub rejected: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PolicyCheckRequest {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub request_canonical_hash: Hash,
    pub action: String,
    pub actor: Did,
    pub source: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub event_preview: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub auth_context: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PolicyCheckResponse {
    pub decision: AuthzDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<Value>,
    pub signature: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MediaIceConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub context: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MediaIceConfigResponse {
    #[serde(default)]
    pub ice_servers: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationReportRequest {
    pub space_id: SpaceId,
    pub target_ref: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub reporter: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ModerationReportResponse {
    pub report_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routed_to: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletPingResponse {
    pub ok: bool,
    pub applet_id: String,
    pub service_did: Did,
    pub protocol_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletDescription {
    pub applet_id: String,
    pub service_did: Did,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub namespaces: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub limits: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub auth: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletTransactionRequest {
    pub source_service_did: Did,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub ephemeral: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletTransactionResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletActorResponse {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletSpaceResponse {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AppletProtocolResponse {
    pub protocol: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_blob: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub field_types: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysUploadRequest {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub one_time_keys: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: BTreeMap<String, Value>,
    pub device_signature: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysUploadResponse {
    pub one_time_key_counts: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysQueryRequest {
    pub device_keys: BTreeMap<Did, Vec<DeviceId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysQueryResponse {
    pub device_keys: BTreeMap<Did, BTreeMap<DeviceId, Value>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysClaimRequest {
    pub one_time_keys: BTreeMap<Did, BTreeMap<DeviceId, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeysClaimResponse {
    pub one_time_keys: BTreeMap<Did, BTreeMap<DeviceId, Value>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesSendRequest {
    pub messages: BTreeMap<Did, BTreeMap<DeviceId, ToDeviceMessage>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct ToDeviceMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_principal_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_principal_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<DeviceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub content: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_proof: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesSendResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delivered: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown_devices: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DeviceMessagesReceiveResponse {
    pub events: Vec<ToDeviceMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_batch: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

// ── Spec-aligned canonical types added in 2026-05 alignment pass ───────────
//
// These types fill gaps identified in `_todos.md` between the Rust SDK
// surface and `contrix-spec/spec/v1/zh/` v1-core-rc.
